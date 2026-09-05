--[[--
Manage the kindle-hid-passthrough daemon and map keys from inside KOReader.

@module koplugin.hidpassthrough
--]]

local ConfirmBox = require("ui/widget/confirmbox")
local Device = require("device")
local Dispatcher = require("dispatcher")
local Event = require("ui/event")
local InfoMessage = require("ui/widget/infomessage")
local InputContainer = require("ui/widget/container/inputcontainer")
local Menu = require("ui/widget/menu")
local PluginShare = require("pluginshare")
local PowerD = Device:getPowerDevice()
local Screen = require("device").screen
local TextViewer = require("ui/widget/textviewer")
local UIManager = require("ui/uimanager")
local logger = require("logger")
local time = require("ui/time")
local rapidjson = require("rapidjson")
local util = require("util")
local ffiutil = require("ffi/util")
local _ = require("gettext")
local T = require("ffi/util").template

local socket = require("socket")
local http = require("socket.http")
local ltn12 = require("ltn12")

local lfs = require("libs/libkoreader-lfs")
local ffi = require("ffi")
local C = ffi.C
local bit = require("bit")
pcall(require, "ffi/posix_h")
pcall(require, "ffi/fbink_input_h")

local HIDPassthrough = InputContainer:extend{
    name = "hidpassthrough",
    is_doc_only = false,

    -- Override in settings/hidpassthrough.lua if your install differs.
    DAEMON_BINARY = "/mnt/us/kindle_hid_passthrough/kindle-hid-passthrough",
    API_HOST      = "127.0.0.1",
    API_PORT      = 8321,
    API_TIMEOUT   = 2, -- seconds
}

------------------------------------------------------------------------------
-- HTTP helper
------------------------------------------------------------------------------

-- Returns the response body or (nil, err).
function HIDPassthrough:_httpGet(path)
    local url = string.format("http://%s:%d%s", self.API_HOST, self.API_PORT, path)
    local body_chunks = {}

    -- socket.http.TIMEOUT is module-global, so save and restore it.
    local saved_timeout = http.TIMEOUT
    http.TIMEOUT = self.API_TIMEOUT

    local ok, code = http.request{
        url = url,
        sink = ltn12.sink.table(body_chunks),
        create = function()
            local s = socket.tcp()
            s:settimeout(self.API_TIMEOUT)
            return s
        end,
    }

    http.TIMEOUT = saved_timeout

    if not ok then
        return nil, tostring(code)
    end
    if code ~= 200 then
        return nil, "HTTP " .. tostring(code)
    end
    return table.concat(body_chunks)
end

function HIDPassthrough:_httpGetJson(path)
    local body, err = self:_httpGet(path)
    if not body then return nil, err end
    local data, perr = rapidjson.decode(body)
    if not data then return nil, "json decode: " .. tostring(perr) end
    return data, nil
end

------------------------------------------------------------------------------
-- Daemon state
------------------------------------------------------------------------------
-- "off" = API server down, "api_only" = server up but daemon stopped,
-- "on" = both. Spawning the binary brings up both layers.

HIDPassthrough.START_TIMEOUT = 15
HIDPassthrough.STOP_TIMEOUT = 5

-- Returns state, body where state is "off" / "api_only" / "on".
function HIDPassthrough:getState()
    local body, err = self:_httpGet("/status")
    if not body then
        logger.dbg("HIDPassthrough: API unreachable:", err)
        return "off", nil
    end
    if body:find('"daemon_running"%s*:%s*true') then
        return "on", body
    end
    return "api_only", body
end

function HIDPassthrough:isRunning()
    return self:getState() == "on"
end

-- The audio bypass is its own switch, not part of HID. It stops the stock
-- audio daemon and puts a mock in its place, which is worth doing only if it
-- works here: on a device where it does not, the reader still needs its own
-- audio, so this has to be something the user can leave off.
function HIDPassthrough:audioEnabled()
    local data = self:_httpGetJson("/audio")
    return data ~= nil and data.enabled == true
end

function HIDPassthrough:setAudioEnabled(want)
    local data, err = self:_httpGetJson("/audio?enable=" .. (want and "1" or "0"))
    if not data then return false, err end
    return data.enabled == want, nil
end

------------------------------------------------------------------------------
-- Key mappings
------------------------------------------------------------------------------
-- Not built on hotkeys.koplugin: it returns disabled unless hasScreenKB or
-- hasKeyboard, which no modern Kindle sets, and PluginLoader caches that.

-- Declared above _attachInput, which fills it.
local input_fds = {}

-- KOReader drops EV_KEY events whose code isn't in event_map. Fill the gaps
-- additively; re-applied on connect/disconnect since externalkeyboard swaps
-- the whole map on attach and restores its snapshot on detach.
function HIDPassthrough:_extendEventMap()
    local map = Device.input and Device.input.event_map
    if not map then
        self._event_map_status = _("KOReader exposes no input event map")
        return
    end

    local path = ffiutil.joinPath(self.path, "event_map_extra.lua")
    local ok, extra = pcall(dofile, path)
    if not ok or type(extra) ~= "table" then
        logger.warn("HIDPassthrough: could not load event_map_extra:", extra)
        self._event_map_status = T(_("FAILED to load %1"), path)
        return
    end

    local added = 0
    for code, name in pairs(extra) do
        if map[code] == nil then
            map[code] = name
            added = added + 1
        end
    end
    self._event_map_status = T(_("%1 extra key codes registered"), tostring(added))
    logger.dbg("HIDPassthrough: added", added, "extra key codes to the event map")
end

------------------------------------------------------------------------------
-- Key device attach
------------------------------------------------------------------------------
-- externalkeyboard matches INPUT_KEYBOARD, which FBInk only sets when keycodes
-- 1..31 are all present, so a remote or gamepad is opened by nobody.

-- Lazy: the fbink_input cdef above is a pcall, so C.INPUT_* at module scope
-- would take the plugin down when it isn't there.
local exclude_types
local function excludeTypes()
    if not exclude_types then
        exclude_types = bit.bor(
            C.INPUT_KEYBOARD,
            C.INPUT_TOUCHSCREEN,
            C.INPUT_TABLET,
            C.INPUT_SCALED_TABLET,
            C.INPUT_ACCELEROMETER,
            C.INPUT_ROTATION_EVENT,
            C.INPUT_KINDLE_FRAME_TAP,
            C.INPUT_POWER_BUTTON,
            C.INPUT_SLEEP_COVER)
    end
    return exclude_types
end

local function checkKeyDevice(path)
    local FBInkInput = ffi.loadlib("fbink_input", 1)
    local dev = FBInkInput.fbink_input_check(path, C.INPUT_KEY, excludeTypes(), 0)
    local info
    if dev ~= nil then
        if dev.matched then
            info = {
                fd   = tonumber(dev.fd),
                path = ffi.string(dev.path),
                name = ffi.string(dev.name),
            }
        end
        C.free(dev)
    end
    return info
end

function HIDPassthrough:_attachInput(path, force)
    if input_fds[path] and not force then return end
    if Device.input.opened_devices[path] and not input_fds[path] then
        logger.dbg("HIDPassthrough: leaving", path, "to KOReader")
        return
    end

    local info = checkKeyDevice(path)
    if not info then
        logger.dbg("HIDPassthrough: cannot open", path, "as a key device")
        return
    end

    -- uhid recreates the node on reconnect; a stale fd makes the input poll
    -- fail with ENODEV and then nothing reaches any plugin.
    if input_fds[info.path] then
        pcall(Device.input.close, Device.input, info.path)
        input_fds[info.path] = nil
    end

    input_fds[info.path] = Device.input:fdopen(info.fd, info.path, info.name)
    logger.info("HIDPassthrough: attached input", info.name, "@", info.path)
    self:_extendEventMap()
end

-- Take a node back that we handed to the mapper. checkKeyDevice deliberately
-- skips keyboards, since externalkeyboard owns those, but it has no idea we
-- closed this one behind its back and will not re-adopt without a reconnect.
-- So open it here regardless of type rather than leave the device dead.
function HIDPassthrough:_reclaimInput(path)
    local FBInkInput = ffi.loadlib("fbink_input", 1)
    local dev = FBInkInput.fbink_input_check(path, C.INPUT_KEY, 0, 0)
    if dev == nil then return false end
    local matched, fd, name = dev.matched, tonumber(dev.fd), ffi.string(dev.name)
    local real = ffi.string(dev.path)
    C.free(dev)
    if not matched then return false end
    input_fds[real] = Device.input:fdopen(fd, real, name)
    logger.info("HIDPassthrough: took", real, "back from Button Mapper")
    self:_extendEventMap()
    return true
end

function HIDPassthrough:_detachInput(path)
    if not input_fds[path] then return end
    Device.input:close(path)
    input_fds[path] = nil
    logger.info("HIDPassthrough: detached input", path)
end

function HIDPassthrough:_scanInputs()
    for name in lfs.dir("/dev/input") do
        if name:match("^event%d+$") then
            self:_attachInput("/dev/input/" .. name)
        end
    end
end

local type_names
local function typeNames()
    if not type_names then
        type_names = {
            { C.INPUT_POINTINGSTICK, "pointingstick" },
            { C.INPUT_MOUSE, "mouse" },
            { C.INPUT_TOUCHPAD, "touchpad" },
            { C.INPUT_TOUCHSCREEN, "touchscreen" },
            { C.INPUT_JOYSTICK, "joystick" },
            { C.INPUT_TABLET, "tablet" },
            { C.INPUT_KEY, "key" },
            { C.INPUT_KEYBOARD, "keyboard" },
            { C.INPUT_ACCELEROMETER, "accelerometer" },
            { C.INPUT_DPAD, "dpad" },
            { C.INPUT_VOLUME_BUTTONS, "volume" },
        }
    end
    return type_names
end

local function describeInput(path)
    local FBInkInput = ffi.loadlib("fbink_input", 1)
    local dev = FBInkInput.fbink_input_check(path, C.INPUT_KEY, 0, C.SCAN_ONLY)
    if dev == nil then return nil end
    local name, dtype = ffi.string(dev.name), dev.type
    C.free(dev)

    local types = {}
    for dummy, pair in ipairs(typeNames()) do -- luacheck: ignore dummy
        if bit.band(dtype, pair[1]) ~= 0 then table.insert(types, pair[2]) end
    end
    return name, #types > 0 and table.concat(types, ",") or "unknown"
end

function HIDPassthrough:showInputDiagnostics()
    local lines = {
        T(_("Extra event map: %1"), self._event_map_status or _("not loaded")),
        T(_("Plugin directory: %1"), tostring(self.path)),
        "",
        _("Input devices:"),
    }

    local paths = {}
    for name in lfs.dir("/dev/input") do
        if name:match("^event%d+$") then
            table.insert(paths, "/dev/input/" .. name)
        end
    end
    table.sort(paths)

    for dummy, path in ipairs(paths) do -- luacheck: ignore dummy
        local name, types = describeInput(path)
        local owner
        if input_fds[path] then
            owner = _("open (this plugin)")
        elseif Device.input.opened_devices[path] then
            owner = _("open (KOReader)")
        else
            owner = _("NOT OPEN - keys are ignored")
        end
        table.insert(lines, T("%1  %2\n    [%3]  %4",
            path, name or "?", types or "?", owner))
    end

    UIManager:show(TextViewer:new{
        title = _("Input diagnostics"),
        text = table.concat(lines, "\n"),
        justified = false,
    })
end

-- An insert is always a new device, so force the re-open. One second, not
-- externalkeyboard's half, so a real keyboard reaches it first.
function HIDPassthrough:onEvdevInputInsert(path)
    UIManager:scheduleIn(1, function() self:_attachInput(path, true) end)
end

function HIDPassthrough:onEvdevInputRemove(path)
    UIManager:scheduleIn(1, function() self:_detachInput(path) end)
end

------------------------------------------------------------------------------
-- Button Mapper frontend
------------------------------------------------------------------------------
-- Gamepads and remotes are the mapper's job (it grabs them and emits plain
-- keys), so their mappings are edited in its config over its helper API
-- rather than in KOReader's event path.

function HIDPassthrough:_mapper()
    if not self._mapper_client then
        self._mapper_client = dofile(self.path .. "/mapper.lua")
    end
    return self._mapper_client
end

function HIDPassthrough:genMapperMenu()
    local mapper = self:_mapper()
    if not mapper.installed() then
        return {{ text = _("Button Mapper is not installed"), enabled = false }}
    end
    local ok, err = mapper.ensureHelper()
    if not ok then
        return {{ text = T(_("Button Mapper unreachable: %1"), tostring(err)), enabled = false }}
    end
    local text = mapper.getConfig()
    if not text then
        return {{ text = _("Could not read the Button Mapper config"), enabled = false }}
    end

    local items = {}
    for dummy, dev in ipairs(mapper.deviceBlocks(text)) do -- luacheck: ignore dummy
        table.insert(items, {
            text = dev.name or dev.id,
            sub_item_table_func = function() return self:genMapperDeviceMenu(dev) end,
        })
    end
    if #items == 0 then
        table.insert(items, {
            text = _("No devices registered yet. Pair one first."),
            enabled = false,
        })
    end
    return items
end

local MAPPER_KINDS = {
    { section = "buttons",  label = _("Button") },
    { section = "dpad",     label = _("D-pad") },
    { section = "triggers", label = _("Trigger") },
}

-- Daemon-side media control, mapped to assets/audio-hack/media.sh.
local MEDIA_ACTIONS = {
    { command = "toggle", title = _("Play/Pause any audio") },
    { command = "pause",  title = _("Pause any audio") },
    { command = "play",   title = _("Resume any audio") },
}

-- Who owns the device node. Only one process can hold an evdev grab, so this
-- is the difference between KOReader seeing the keys and the mapper seeing
-- them. `grab` absent means the daemon decides from the node itself.
local MAPPER_MODES = {
    {
        title = _("Automatic"),
        note = _("Gamepads are taken over, keyboards are left to KOReader."),
        grab = nil, passthrough = nil,
    },
    {
        title = _("KOReader only"),
        note = _("Button Mapper leaves this device alone. Mappings won't fire."),
        grab = "false", passthrough = nil,
    },
    {
        title = _("Button Mapper, keys still type"),
        note = _("Mapped buttons run their action, everything else is passed through untouched."),
        grab = "true", passthrough = "true",
    },
    {
        title = _("Button Mapper, exclusive"),
        note = _("Mapped buttons run their action, everything else does nothing."),
        grab = "true", passthrough = "false",
    },
}

function HIDPassthrough:_mapperMode(dev)
    local text = self:_mapper().getConfig() or ""
    local section = "device." .. dev.id
    local grab = self:_mapper().sectionValue(text, section, "grab")
    local passthrough = self:_mapper().sectionValue(text, section, "passthrough")
    for dummy, mode in ipairs(MAPPER_MODES) do -- luacheck: ignore dummy
        if mode.grab == grab and (mode.grab ~= "true" or mode.passthrough == passthrough) then
            return mode
        end
    end
    return MAPPER_MODES[1]
end

-- Only one process can hold an evdev grab, and KOReader takes one on every
-- node it opens. So the mapper cannot claim a keyboard while KOReader has it,
-- and the mode the user picked has to be matched by actually letting go.
local function releaseNode(path)
    input_fds[path] = nil
    local ok, err = pcall(Device.input.close, Device.input, path)
    if ok then
        logger.info("HIDPassthrough: released", path, "for Button Mapper")
    else
        logger.dbg("HIDPassthrough: nothing to release at", path, err)
    end
end

function HIDPassthrough:_applyMapperMode(dev, mode)
    local node = self:_mapper().findNode(dev.uniq or "")
    -- Hand the node over before the daemon is told to take it, and take it
    -- back only after the daemon has been told to let go.
    if node and mode.grab == "true" then
        releaseNode(node)
    end

    local ok = self:mapperEdit(function(cur)
        local section = "device." .. dev.id
        for dummy, key in ipairs({ "grab", "passthrough" }) do -- luacheck: ignore dummy
            if mode[key] then
                cur = self:_mapper().setKey(cur, section, key, mode[key])
            else
                cur = self:_mapper().removeKey(cur, section, key)
            end
        end
        return cur
    end)

    if node and ok and mode.grab ~= "true" then
        -- The daemon ungrabs on its own reload tick, so give it a moment
        -- before reopening or this grab lands while it still holds one.
        -- Drop whatever KOReader still thinks it has first: handing the node
        -- over leaves a stale entry that would make the reopen a no-op, and
        -- then the device would be dead here until KOReader restarts.
        UIManager:scheduleIn(1.5, function()
            releaseNode(node)
            if not self:_reclaimInput(node) then
                logger.warn("HIDPassthrough: could not take", node, "back from Button Mapper")
                UIManager:show(InfoMessage:new{
                    text = _("Reconnect the device for KOReader to pick it up again."),
                    timeout = 4,
                })
            end
        end)
    end
    return ok
end

function HIDPassthrough:genMapperModeMenu(dev)
    local items = {}
    for dummy, mode in ipairs(MAPPER_MODES) do -- luacheck: ignore dummy
        table.insert(items, {
            text = mode.title,
            help_text = mode.note,
            radio = true,
            checked_func = function() return self:_mapperMode(dev).title == mode.title end,
            callback = function(touchmenu_instance)
                self:_applyMapperMode(dev, mode)
                if touchmenu_instance then touchmenu_instance:updateItems() end
            end,
        })
    end
    return items
end

function HIDPassthrough:genMapperDeviceMenu(dev)
    local mapper = self:_mapper()
    local items = {
        {
            text_func = function()
                return T(_("Handled by: %1"), self:_mapperMode(dev).title)
            end,
            sub_item_table_func = function() return self:genMapperModeMenu(dev) end,
        },
        {
            text = _("Map a button…"),
            keep_menu_open = true,
            callback = function(touchmenu_instance)
                self:mapperCapture(dev, touchmenu_instance,
                    #touchmenu_instance.item_table_stack)
            end,
            separator = true,
        },
    }

    local text = mapper.getConfig() or ""
    for dummy, kind in ipairs(MAPPER_KINDS) do -- luacheck: ignore dummy
        local section = "device." .. dev.id .. "." .. kind.section
        for dummy2, entry in ipairs(mapper.sectionKeys(text, section)) do -- luacheck: ignore dummy2
            local action = mapper.describeScript(entry.value, self:_actionTitles())
            local label = T("%1 %2", kind.label, entry.key)
            table.insert(items, {
                text = T("%1  →  %2", label, action),
                keep_menu_open = true,
                sub_item_table_func = function()
                    return self:genMappingMenu(dev, section, entry.key, label)
                end,
                ignored_by_menu_search = true,
            })
        end
    end

    -- The mode entry and "Map a button…" are always there, so anything past
    -- them is a real mapping. Only a gamepad gets a layout for free, the
    -- mapper leaves anything else alone until something here names a button,
    -- so don't promise defaults that a keyboard will never have.
    if #items == 2 then
        table.insert(items, {
            text = _("(nothing mapped — gamepads get defaults)"),
            enabled = false,
        })
    end
    items.refresh_func = function() return self:genMapperDeviceMenu(dev) end
    return items
end

-- What one already-mapped control offers. A submenu rather than a hold, so
-- removing is discoverable and TouchMenu's own back arrow gets you out.
function HIDPassthrough:genMappingMenu(dev, section, key, label)
    local mapper = self:_mapper()
    return {
        {
            text = _("Change action…"),
            keep_menu_open = true,
            callback = function(touchmenu_instance)
                -- This submenu sits one level below the device list.
                self:pushActionPicker(dev, section, key, label,
                    #touchmenu_instance.item_table_stack - 1, touchmenu_instance)
            end,
        },
        {
            text = _("Remove this mapping"),
            keep_menu_open = true,
            callback = function(touchmenu_instance)
                UIManager:show(ConfirmBox:new{
                    text = T(_("Remove the mapping for %1?"), label),
                    ok_text = _("Remove"),
                    ok_callback = function()
                        self:mapperEdit(function(cur)
                            return mapper.removeKey(cur, section, key)
                        end)
                        if touchmenu_instance then
                            -- Mark the parent stale so its refresh_func rebuilds.
                            local stack = touchmenu_instance.item_table_stack
                            local parent = stack and stack[#stack]
                            if parent then parent.needs_refresh = true end
                            touchmenu_instance:backToUpperMenu()
                        end
                    end,
                })
            end,
        },
    }
end

-- Re-fetch, transform, write back, reload. The helper serializes writers, but
-- editing a stale text would still drop someone else's change, so keep the
-- window small by fetching right before the edit.
function HIDPassthrough:mapperEdit(transform)
    local mapper = self:_mapper()
    local text = mapper.getConfig()
    if not text then
        UIManager:show(InfoMessage:new{ text = _("Could not read the Button Mapper config.") })
        return false
    end
    local ok, err = mapper.setConfig(transform(text))
    if not ok then
        UIManager:show(InfoMessage:new{ text = T(_("Saving failed: %1"), tostring(err)) })
        return false
    end
    mapper.reload()
    return true
end

function HIDPassthrough:mapperCapture(dev, touchmenu_instance, device_depth)
    local mapper = self:_mapper()
    local node = mapper.findNode(dev.uniq or "")
    if not node then
        UIManager:show(InfoMessage:new{
            text = T(_("%1 is not connected."), dev.name or dev.id),
        })
        return
    end

    local msg = InfoMessage:new{
        text = _("Press a button or D-pad direction on the controller…"),
    }
    UIManager:show(msg)
    -- Painted first; the capture request then blocks the UI until a press
    -- or the helper's timeout. Whatever the menu was showing then is what
    -- the picker has to be pushed onto, so remember it and check on the way
    -- back rather than pushing onto whatever the user browsed to meanwhile.
    local menu_at_start = touchmenu_instance and touchmenu_instance.item_table
    -- The mapper does the capture, not us, and only one process can hold an
    -- evdev grab. While KOReader holds this node the mapper's reader gets
    -- nothing and every capture ends in a timeout, so hand the node over for
    -- the length of the call. Nothing to do when the mode already gave it away.
    local held = input_fds[node] ~= nil
    if held then releaseNode(node) end
    UIManager:scheduleIn(0.1, function()
        local cap, err = mapper.capture(node, 8000)
        if held then
            -- The capture reader lets go when the call returns; give it the
            -- same moment _applyMapperMode does before grabbing again, and
            -- drop our stale entry first or the reopen is a no-op.
            UIManager:scheduleIn(1.5, function()
                releaseNode(node)
                if not self:_reclaimInput(node) then
                    logger.warn("HIDPassthrough: could not take", node,
                        "back after capture")
                    UIManager:show(InfoMessage:new{
                        text = _("Reconnect the device for KOReader to pick it up again."),
                        timeout = 4,
                    })
                end
            end)
        end
        UIManager:close(msg)
        if not cap then
            UIManager:show(InfoMessage:new{
                text = T(_("Nothing captured: %1"), tostring(err or "timeout")),
                timeout = 3,
            })
            return
        end
        local section, key, label = mapper.captureTarget(dev.id, cap)
        if not section then
            UIManager:show(InfoMessage:new{
                text = _("That input isn't mappable here."),
                timeout = 3,
            })
            return
        end
        if not touchmenu_instance then return end
        if touchmenu_instance.item_table ~= menu_at_start then
            UIManager:show(InfoMessage:new{
                text = T(_("Captured %1. Open it from the list to pick an action."), label),
                timeout = 3,
            })
            return
        end
        self:pushActionPicker(dev, section, key, label, device_depth, touchmenu_instance)
    end)
end

-- Event name to title, for labelling mappings already in the config.
-- Every script the picker can write, mapped back to the wording it was picked
-- under, so an already-configured mapping reads as "Toggle night mode" rather
-- than "koreader.sh night_mode". Keyed by script line and, for KOReader events,
-- by bare event name too, since those can also arrive from the mapper's own app.
function HIDPassthrough:_actionTitles()
    if not self._action_titles then
        local titles = {}
        for dummy, group in ipairs(self:_actionSections()) do -- luacheck: ignore dummy
            for dummy2, item in ipairs(group.items) do -- luacheck: ignore dummy2
                titles[item.script] = item.title
                local event = item.script:match("koreader%.sh event ([%w_]+)$")
                if event then titles[event] = item.title end
            end
        end
        self._action_titles = titles
    end
    return self._action_titles
end

-- KOReader's own actions, plus the mapper's native ones for the cases KOReader
-- cannot do (native reader page turns, screen taps, brightness over lipc).
-- What people actually bind, in the order they reach for it. The auto.* ones
-- try KOReader first and fall back to the native reader, so a favourite keeps
-- working outside KOReader, which the KOReader event list cannot do.
local FAVORITE_ACTIONS = {
    { kind = "auto",     id = "next_page" },
    { kind = "auto",     id = "prev_page" },
    { kind = "auto",     id = "menu" },
    { kind = "koreader", id = "night_mode" },
    { kind = "auto",     id = "brightness 1" },
    { kind = "auto",     id = "brightness -1" },
    { kind = "auto",     id = "brightness_toggle" },
    { kind = "koreader", id = "font_up 1" },
    { kind = "koreader", id = "font_down 1" },
    { kind = "koreader", id = "toggle_status_bar" },
    { kind = "koreader", id = "rotate" },
}

function HIDPassthrough:_actionSections()
    if not self._action_sections then
        local sections = {}
        local native = self:_mapper().actions()

        if native then
            local by_key = {}
            for dummy, a in ipairs(native) do -- luacheck: ignore dummy
                by_key[a.kind .. "\0" .. a.id] = a
            end
            local items = {}
            for dummy, fav in ipairs(FAVORITE_ACTIONS) do -- luacheck: ignore dummy
                local a = by_key[fav.kind .. "\0" .. fav.id]
                if a then
                    table.insert(items, {
                        title = a.label,
                        script = self:_mapper().actionScript(a),
                    })
                end
            end
            if #items > 0 then
                table.insert(sections, { title = _("Favorites"), items = items })
            end
        end

        -- The daemon pauses by holding its own audio FIFO, so this stops
        -- whatever is playing without the application cooperating. It replaced
        -- the per-plugin audiobook events this branch used to list: those only
        -- reach the plugin that owns the playback and do nothing otherwise.
        if util.pathExists(self:_mapper().MEDIA) then
            local items = {}
            for dummy, a in ipairs(MEDIA_ACTIONS) do -- luacheck: ignore dummy
                table.insert(items, {
                    title = a.title,
                    script = self:_mapper().mediaScript(a.command),
                })
            end
            table.insert(sections, { title = _("Audio"), items = items })
        end

        local ok, koactions = pcall(dofile,
            ffiutil.joinPath(self.path, "koreader_actions.lua"))
        if ok and type(koactions) == "table" then
            for dummy, group in ipairs(koactions) do -- luacheck: ignore dummy
                local items = {}
                for dummy2, a in ipairs(group.actions) do -- luacheck: ignore dummy2
                    table.insert(items, {
                        title = a.title,
                        script = self:_mapper().koreaderEventScript(a.event),
                    })
                end
                table.insert(sections, { title = group.section, items = items })
            end
        else
            logger.warn("HIDPassthrough: could not load koreader_actions:", koactions)
        end

        -- Split by what the script actually drives rather than lumping both
        -- under one "native" heading: auto.* try KOReader first and fall back
        -- to the Kindle reader, kindle.* only ever drive the Kindle reader.
        -- The koreader.* ones duplicate the KOReader list above.
        local NATIVE_GROUPS = {
            { kind = "auto",   title = _("Works outside KOReader too") },
            { kind = "kindle", title = _("Native Kindle reader") },
        }
        if native then
            for dummy, group in ipairs(NATIVE_GROUPS) do -- luacheck: ignore dummy
                local items = {}
                for dummy2, a in ipairs(native) do -- luacheck: ignore dummy2
                    if a.kind == group.kind then
                        table.insert(items, {
                            title = a.label,
                            script = self:_mapper().actionScript(a),
                        })
                    end
                end
                if #items > 0 then
                    table.insert(sections, { title = group.title, items = items })
                end
            end
        end
        self._action_sections = sections
    end
    return self._action_sections
end

-- The action picker lives inside the TouchMenu we were called from rather
-- than in a Menu of its own. A second full-screen widget layered over the
-- TouchMenu fought it for input, which is why finishing any of these flows
-- dumped you back at the top menu.
--
-- device_depth is the stack length at which item_table is the device list, so
-- assigning can unwind straight back to it.
function HIDPassthrough:pushActionPicker(dev, section, key, label, device_depth, touchmenu)
    local sections = self:_actionSections()
    if #sections == 0 then
        UIManager:show(InfoMessage:new{ text = _("No actions available.") })
        return
    end

    local items = {}
    for dummy, group in ipairs(sections) do -- luacheck: ignore dummy
        table.insert(items, {
            text = T("%1  (%2)", group.title, tostring(#group.items)),
            sub_item_table_func = function()
                local sub = {}
                for dummy2, action in ipairs(group.items) do -- luacheck: ignore dummy2
                    table.insert(sub, {
                        text = action.title,
                        keep_menu_open = true,
                        callback = function(inner)
                            self:mapperAssign(dev, section, key, label, action,
                                device_depth, inner)
                        end,
                    })
                end
                return sub
            end,
        })
    end

    -- Same two steps onMenuSelect takes for a sub_item_table, so the back
    -- arrow and paging behave exactly as they do everywhere else.
    table.insert(touchmenu.item_table_stack, touchmenu.item_table)
    touchmenu.item_table = items
    touchmenu:updateItems(1)
end

function HIDPassthrough:mapperAssign(dev, section, key, label, action, device_depth, touchmenu)
    local mapper = self:_mapper()
    if not self:mapperEdit(function(cur)
        return mapper.setKey(cur, section, key, action.script)
    end) then
        return
    end

    if touchmenu then
        -- Unwind to the device list, then rebuild it so the new mapping shows
        -- and the next button is one tap away.
        while #touchmenu.item_table_stack > device_depth do
            touchmenu.item_table = table.remove(touchmenu.item_table_stack)
        end
        touchmenu.item_table = self:genMapperDeviceMenu(dev)
        touchmenu:updateItems(1)
    end
    UIManager:show(InfoMessage:new{
        text = T(_("Mapped %1 to %2."), label, action.title),
        timeout = 2,
    })
end

------------------------------------------------------------------------------
-- Start / stop
------------------------------------------------------------------------------

-- Spawn the binary detached. Used only when the API server itself is down.
function HIDPassthrough:_spawnBinary()
    if not util.pathExists(self.DAEMON_BINARY) then
        return false, T(_("Daemon binary not found at %1."), self.DAEMON_BINARY)
    end
    -- setsid so it survives KOReader exiting; exit code is meaningless.
    local cmd = string.format(
        "(setsid %s --daemon </dev/null >>/mnt/us/kindle_hid_passthrough/daemon.log 2>&1 &) 2>/dev/null || "
        .. "(%s --daemon </dev/null >>/mnt/us/kindle_hid_passthrough/daemon.log 2>&1 &)",
        self.DAEMON_BINARY, self.DAEMON_BINARY
    )
    logger.info("HIDPassthrough: spawning daemon:", cmd)
    os.execute(cmd)
    return true
end

-- Wait until getState() reports the desired state, or timeout.
function HIDPassthrough:_waitForState(target, timeout)
    for i = 1, timeout do
        ffiutil.sleep(1)
        local state = self:getState()
        logger.dbg("HIDPassthrough: waiting for", target, "got", state, "tick", i)
        if state == target then
            return true
        end
    end
    return false
end

function HIDPassthrough:start()
    local state = self:getState()

    if state == "on" then
        return true, _("HID Passthrough daemon is already running.")
    end

    if state == "off" then
        -- API server not up. Spawn the binary, which brings up both layers.
        local ok, err = self:_spawnBinary()
        if not ok then return false, err end

        if self:_waitForState("on", self.START_TIMEOUT) then
            return true, _("HID Passthrough daemon started.")
        end

        -- Didn't reach "on". Figure out which sub-failure to report.
        local final = self:getState()
        if final == "off" then
            return false, _("Daemon failed to start: API server never came up. "
                .. "Try running the binary manually from a shell to see the error.")
        end
        -- final == "api_only": API server is alive but HID daemon didn't start.
        -- One last attempt via /start, in case it just needs a nudge.
        logger.info("HIDPassthrough: API up but daemon off, calling /start")
        if self:_httpGet("/start") and self:_waitForState("on", self.START_TIMEOUT) then
            return true, _("HID Passthrough daemon started.")
        end
        return false, T(_("API server is up but the HID daemon would not start "
            .. "within %1 seconds. Check /var/log/hid_passthrough.log."),
            tostring(self.START_TIMEOUT))
    end

    -- state == "api_only": just ask the API server to start the daemon.
    logger.info("HIDPassthrough: API up, calling /start")
    local body, err = self:_httpGet("/start")
    if not body then
        return false, T(_("API call to /start failed: %1"), tostring(err))
    end
    if self:_waitForState("on", self.START_TIMEOUT) then
        return true, _("HID Passthrough daemon started.")
    end
    return false, T(_("/start was accepted but daemon did not come up within "
        .. "%1 seconds. Check /var/log/hid_passthrough.log."),
        tostring(self.START_TIMEOUT))
end

function HIDPassthrough:stop()
    local state = self:getState()

    if state ~= "on" then
        -- Either nothing is running, or only the API server is up (which is
        -- the idle state we want). Either way, no work to do.
        return true, _("HID Passthrough daemon is not running.")
    end

    -- Ask the API server to stop the HID daemon. The API server itself stays
    -- up, matching the BTManager behavior — that way the next /start is fast.
    local body, err = self:_httpGet("/stop")
    if not body then
        return false, T(_("API call to /stop failed: %1"), tostring(err))
    end

    -- Wait for daemon_running to flip to false.
    for i = 1, self.STOP_TIMEOUT do
        ffiutil.sleep(1)
        if self:getState() ~= "on" then
            return true, _("HID Passthrough daemon stopped.")
        end
        logger.dbg("HIDPassthrough: waiting for stop, tick", i)
    end
    return false, _("Daemon did not stop within timeout.")
end

function HIDPassthrough:toggle()
    if self:isRunning() then
        return self:stop()
    else
        return self:start()
    end
end

------------------------------------------------------------------------------
-- Info dialog: parse a few fields out of /status for display
------------------------------------------------------------------------------

local function extractField(body, key)
    if not body then return nil end
    -- Try string value first.
    local v = body:match('"' .. key .. '"%s*:%s*"([^"]*)"')
    if v then return v end
    -- Then numeric / boolean.
    v = body:match('"' .. key .. '"%s*:%s*([%w%.%-]+)')
    return v
end

local function countDevices(body)
    if not body then return nil end
    -- Count opening braces inside the "devices" array.
    local arr = body:match('"devices"%s*:%s*(%b[])')
    if not arr then return nil end
    local n = 0
    for _ in arr:gmatch("{") do n = n + 1 end
    return n
end

function HIDPassthrough:showInfo()
    local state, body = self:getState()
    local lines = {}

    if state == "on" then
        table.insert(lines, _("Status: HID daemon running"))
    elseif state == "api_only" then
        table.insert(lines, _("Status: API server up, HID daemon stopped"))
    else
        table.insert(lines, _("Status: not running"))
    end

    if body then
        local version = extractField(body, "version")
        if version then
            table.insert(lines, T(_("Version: %1"), version))
        end

        local n_devices = countDevices(body)
        if n_devices then
            table.insert(lines, T(_("Configured devices: %1"), tostring(n_devices)))
        end

        local connected = {}
        local okj, data = pcall(rapidjson.decode, body)
        if okj and type(data) == "table" and type(data.connections) == "table" then
            for _, conn in ipairs(data.connections) do
                table.insert(connected, conn.name or conn.address or "?")
            end
        end
        if #connected > 0 then
            table.insert(lines, T(_("Connected (%1): %2"),
                tostring(#connected), table.concat(connected, ", ")))
        end

        if body:find('"scanning"%s*:%s*true') then
            table.insert(lines, _("Currently scanning…"))
        end
        if body:find('"pairing"%s*:%s*true') then
            table.insert(lines, _("Currently pairing…"))
        end
    end

    -- The mapper is the other half of this plugin now, so a status panel that
    -- only covers the Bluetooth side answers half the question.
    table.insert(lines, "")
    local mapper = self:_mapper()
    if not mapper.installed() then
        table.insert(lines, _("Button Mapper: not installed"))
    else
        local status = mapper.status()
        if not status then
            table.insert(lines, _("Button Mapper: helper not reachable"))
        else
            local running = status.running and _("running") or _("stopped")
            local version = status.version or "?"
            if status.build then version = version .. "-" .. status.build end
            table.insert(lines, T(_("Button Mapper: %1 (%2)"), running, version))
        end
    end

    table.insert(lines, "")
    table.insert(lines, T(_("Binary: %1"), self.DAEMON_BINARY))
    table.insert(lines, T(_("API: http://%1:%2"), self.API_HOST, tostring(self.API_PORT)))

    UIManager:show(InfoMessage:new{
        text = table.concat(lines, "\n"),
    })
end

HIDPassthrough.SCAN_POLL_INTERVAL = 2
HIDPassthrough.PAIR_POLL_INTERVAL = 2
HIDPassthrough.SCAN_TIMEOUT_TICKS = 30

local function urlEncode(s)
    if s == nil then return "" end
    return (tostring(s):gsub("[^%w%-_.~]", function(c)
        return string.format("%%%02X", string.byte(c))
    end))
end

function HIDPassthrough:_cancelPolls()
    if self._scan_poll_cb then
        UIManager:unschedule(self._scan_poll_cb)
        self._scan_poll_cb = nil
    end
    if self._pair_poll_cb then
        UIManager:unschedule(self._pair_poll_cb)
        self._pair_poll_cb = nil
    end
end

local function infoToast(text, is_error)
    UIManager:show(InfoMessage:new{
        text = text,
        timeout = is_error and 4 or 2,
    })
end

local function deviceLabel(dev)
    local name = dev.name
    if name == nil or name == "" then name = dev.address or "?" end
    local proto = dev.protocol
    if proto and proto ~= "" then
        return name .. "  (" .. proto:upper() .. ")"
    end
    return name
end

local function setMenuItems(menu, items, title)
    menu:switchItemTable(title, items, 1)
end

function HIDPassthrough:scanForDevices()
    if not self:isRunning() then
        infoToast(_("Daemon is not running. Start it first."), true)
        return
    end
    self:_cancelPolls()

    local menu
    menu = Menu:new{
        title = _("Scanning…"),
        item_table = {{ text = _("Scanning… (no devices yet)"), dim = true }},
        width = Screen:getWidth(),
        height = Screen:getHeight(),
        is_popout = false,
        onClose = function()
            self:_cancelPolls()
            UIManager:close(menu)
            self:_httpGet("/scan-stop")
        end,
    }
    self._scan_menu = menu
    UIManager:show(menu)

    local body, err = self:_httpGet("/scan")
    if not body then
        UIManager:close(menu)
        infoToast(T(_("Scan failed: %1"), tostring(err)), true)
        return
    end
    self:_pollScan(0)
end

function HIDPassthrough:_pollScan(tick)
    self._scan_poll_cb = function() self:_doPollScan(tick) end
    UIManager:scheduleIn(self.SCAN_POLL_INTERVAL, self._scan_poll_cb)
end

function HIDPassthrough:_doPollScan(tick)
    self._scan_poll_cb = nil
    if not self._scan_menu then return end

    local data, err = self:_httpGetJson("/scan-status")
    if not data then
        UIManager:close(self._scan_menu)
        self._scan_menu = nil
        infoToast(T(_("Scan error: %1"), tostring(err)), true)
        return
    end

    local devices = data.devices or {}
    if data.scanning then
        if #devices > 0 then
            setMenuItems(self._scan_menu, self:_buildScanItems(devices),
                T(_("Scanning… (%1)"), tostring(#devices)))
        end
        if tick >= self.SCAN_TIMEOUT_TICKS then
            self:_httpGet("/scan-stop")
        end
        self:_pollScan(tick + 1)
        return
    end

    if data.ok and #devices > 0 then
        setMenuItems(self._scan_menu, self:_buildScanItems(devices),
            T(_("Scan Results (%1)"), tostring(#devices)))
    else
        UIManager:close(self._scan_menu)
        self._scan_menu = nil
        if data.error then
            infoToast(T(_("Scan failed: %1"), data.error), true)
        else
            infoToast(_("No HID devices found"))
        end
    end
end

function HIDPassthrough:_buildScanItems(devices)
    local items = {}
    for _, dev in ipairs(devices) do
        local addr = dev.address
        local proto = dev.protocol or "ble"
        local name = dev.name or ""
        table.insert(items, {
            text = deviceLabel(dev),
            callback = function()
                if self._scan_menu then
                    UIManager:close(self._scan_menu)
                    self._scan_menu = nil
                end
                self:_cancelPolls()
                self:_httpGet("/scan-stop")
                self:pairDevice(addr, proto, name)
            end,
        })
    end
    return items
end

function HIDPassthrough:pairDevice(addr, protocol, name)
    self:_cancelPolls()

    local msg = InfoMessage:new{
        text = T(_("Pairing %1…"), addr),
        dismissable = true,
    }
    self._pair_msg = msg
    UIManager:show(msg)

    local url = "/pair?addr=" .. urlEncode(addr)
        .. "&protocol=" .. urlEncode(protocol or "ble")
    if name and name ~= "" then
        url = url .. "&name=" .. urlEncode(name)
    end

    local body, err = self:_httpGet(url)
    if not body then
        UIManager:close(msg)
        self._pair_msg = nil
        infoToast(T(_("Pair error: %1"), tostring(err)), true)
        return
    end
    self:_pollPair(0)
end

function HIDPassthrough:_pollPair(tick)
    self._pair_poll_cb = function() self:_doPollPair(tick) end
    UIManager:scheduleIn(self.PAIR_POLL_INTERVAL, self._pair_poll_cb)
end

function HIDPassthrough:_doPollPair(tick)
    self._pair_poll_cb = nil
    local data, err = self:_httpGetJson("/pair-status")
    if not data then
        if self._pair_msg then UIManager:close(self._pair_msg); self._pair_msg = nil end
        infoToast(T(_("Pair error: %1"), tostring(err)), true)
        return
    end

    if data.pairing then
        if tick > 30 then
            if self._pair_msg then UIManager:close(self._pair_msg); self._pair_msg = nil end
            infoToast(_("Pairing timed out"), true)
            return
        end
        self:_pollPair(tick + 1)
        return
    end

    if self._pair_msg then UIManager:close(self._pair_msg); self._pair_msg = nil end
    if data.ok then
        infoToast(T(_("Paired: %1"), data.address or ""))
        self:_afterDeviceAction()
    else
        infoToast(T(_("Pairing failed: %1"), data.error or _("unknown")), true)
    end
end

function HIDPassthrough:showPairedDevices()
    local data, err = self:_httpGetJson("/status")
    if not data then
        infoToast(T(_("Cannot reach daemon: %1"), tostring(err)), true)
        return
    end
    local devices = data.devices or {}
    if #devices == 0 then
        infoToast(_("No paired devices. Use Scan to add one."))
        return
    end

    local connected = {}
    if type(data.connections) == "table" then
        for _, conn in ipairs(data.connections) do
            if conn.address then
                connected[conn.address:upper()] = true
            end
        end
    end
    local items = {}
    for _, dev in ipairs(devices) do
        local is_conn = (dev.address and connected[dev.address:upper()]) or false
        local prefix = is_conn and "● " or "○ "
        local addr  = dev.address
        local proto = dev.protocol or "ble"
        local name  = dev.name or ""
        table.insert(items, {
            text = prefix .. deviceLabel(dev),
            callback = function()
                if self._paired_menu then
                    UIManager:close(self._paired_menu)
                    self._paired_menu = nil
                end
                self:_showDeviceActions(addr, proto, name, is_conn)
            end,
        })
    end

    local menu
    menu = Menu:new{
        title = _("Paired Devices"),
        item_table = items,
        width = Screen:getWidth(),
        height = Screen:getHeight(),
        is_popout = false,
        onClose = function()
            UIManager:close(menu)
            self._paired_menu = nil
        end,
    }
    self._paired_menu = menu
    UIManager:show(menu)
end

-- The Bluetooth list and the mapper's device list are keyed differently, one
-- by pairing address and one by config block, so match on the bare MAC.
function HIDPassthrough:_mapperDeviceFor(addr)
    local mapper = self:_mapper()
    if not mapper.installed() then return nil end
    local text = mapper.getConfig()
    if not text then return nil end
    local want = mapper.bareAddr(addr)
    for dummy, dev in ipairs(mapper.deviceBlocks(text)) do -- luacheck: ignore dummy
        if dev.uniq and mapper.bareAddr(dev.uniq) == want then return dev end
    end
end

function HIDPassthrough:_showMapperModePicker(mdev, addr, proto, name, is_connected)
    local items = {}
    for dummy, mode in ipairs(MAPPER_MODES) do -- luacheck: ignore dummy
        local current = self:_mapperMode(mdev).title == mode.title
        table.insert(items, {
            text = (current and "● " or "○ ") .. mode.title,
            callback = function()
                UIManager:close(self._mode_menu)
                self._mode_menu = nil
                self:_applyMapperMode(mdev, mode)
                self:_showDeviceActions(addr, proto, name, is_connected)
            end,
        })
    end

    local menu
    menu = Menu:new{
        title = mdev.name or mdev.id,
        subtitle = _("Who reads this device"),
        item_table = items,
        width = Screen:getWidth(),
        height = Screen:getHeight(),
        is_popout = false,
        onClose = function()
            UIManager:close(menu)
            self._mode_menu = nil
            self:_showDeviceActions(addr, proto, name, is_connected)
        end,
    }
    self._mode_menu = menu
    UIManager:show(menu)
end

function HIDPassthrough:_showDeviceActions(addr, proto, name, is_connected)
    local label = (name and name ~= "" and name) or addr
    local items = {}
    if is_connected then
        table.insert(items, {
            text = _("Disconnect"),
            callback = function()
                UIManager:close(self._action_menu)
                self._action_menu = nil
                self:_disconnectDevice(addr)
            end,
        })
    else
        table.insert(items, {
            text = _("Connect"),
            callback = function()
                UIManager:close(self._action_menu)
                self._action_menu = nil
                self:_connectDevice(addr, proto)
            end,
        })
    end
    -- Same setting as the one under Key mappings, written through the same
    -- code. This is where people look for it, so offer it here too.
    local mdev = self:_mapperDeviceFor(addr)
    if mdev then
        table.insert(items, {
            text = T(_("Handled by: %1"), self:_mapperMode(mdev).title),
            callback = function()
                UIManager:close(self._action_menu)
                self._action_menu = nil
                self:_showMapperModePicker(mdev, addr, proto, name, is_connected)
            end,
        })
    end

    table.insert(items, {
        text = _("Remove (forget)"),
        callback = function()
            UIManager:close(self._action_menu)
            self._action_menu = nil
            UIManager:show(ConfirmBox:new{
                text = T(_("Remove device %1?"), addr),
                ok_text = _("Remove"),
                ok_callback = function() self:_removeDevice(addr) end,
            })
        end,
    })

    local menu
    menu = Menu:new{
        title = label,
        item_table = items,
        width = Screen:getWidth(),
        height = Screen:getHeight(),
        is_popout = false,
        onClose = function()
            UIManager:close(menu)
            self._action_menu = nil
        end,
    }
    self._action_menu = menu
    UIManager:show(menu)
end

function HIDPassthrough:_afterDeviceAction()
    UIManager:scheduleIn(0.4, function() self:showPairedDevices() end)
end

function HIDPassthrough:_connectDevice(addr, proto)
    infoToast(T(_("Connecting %1…"), addr))
    UIManager:nextTick(function()
        local url = "/connect?addr=" .. urlEncode(addr)
            .. "&protocol=" .. urlEncode(proto or "ble")
        local data, err = self:_httpGetJson(url)
        if not data then
            infoToast(T(_("Connect error: %1"), tostring(err)), true)
            return
        end
        if data.ok then
            infoToast(_("Connect requested"))
        else
            infoToast(T(_("Connect failed: %1"), data.error or _("unknown")), true)
        end
        self:_afterDeviceAction()
    end)
end

function HIDPassthrough:_disconnectDevice(addr)
    infoToast(T(_("Disconnecting %1…"), addr))
    UIManager:nextTick(function()
        local data, err = self:_httpGetJson("/disconnect?addr=" .. urlEncode(addr))
        if not data then
            infoToast(T(_("Disconnect error: %1"), tostring(err)), true)
            return
        end
        if data.ok then
            infoToast(_("Disconnected"))
        else
            infoToast(T(_("Disconnect failed: %1"), data.error or _("unknown")), true)
        end
        self:_afterDeviceAction()
    end)
end

function HIDPassthrough:_removeDevice(addr)
    infoToast(T(_("Removing %1…"), addr))
    UIManager:nextTick(function()
        local data, err = self:_httpGetJson("/remove?addr=" .. urlEncode(addr))
        if not data then
            infoToast(T(_("Remove error: %1"), tostring(err)), true)
            return
        end
        if data.ok then
            infoToast(_("Device removed"))
        else
            infoToast(T(_("Remove failed: %1"), data.error or _("unknown")), true)
        end
        self:_afterDeviceAction()
    end)
end

HIDPassthrough.LOG_LINES = 100

function HIDPassthrough:showLogs()
    local data, err = self:_httpGetJson("/logs?lines=" .. tostring(self.LOG_LINES))
    local text
    if not data then
        text = T(_("Could not fetch logs: %1"), tostring(err))
    elseif data.lines and #data.lines > 0 then
        text = table.concat(data.lines, "\n")
    else
        text = _("(no log lines)")
    end

    local viewer
    viewer = TextViewer:new{
        title = _("Recent logs"),
        text = text,
        justified = false,
        buttons_table = {
            {
                {
                    text = _("Refresh"),
                    callback = function()
                        UIManager:close(viewer)
                        self:showLogs()
                    end,
                },
                {
                    text = _("Close"),
                    callback = function() UIManager:close(viewer) end,
                },
            },
        },
    }
    UIManager:show(viewer)
    -- Open on the newest lines, like tail.
    if viewer.scroll_widget then
        viewer.scroll_widget:scrollToBottom()
    end
end

function HIDPassthrough:clearCache()
    UIManager:show(ConfirmBox:new{
        text = _("Clear all cached HID descriptors?"),
        ok_text = _("Clear"),
        ok_callback = function()
            UIManager:nextTick(function()
                local data, err = self:_httpGetJson("/clear-cache")
                if not data then
                    infoToast(T(_("Clear cache error: %1"), tostring(err)), true)
                    return
                end
                if data.ok then
                    local n = data.files_removed
                    if n then
                        infoToast(T(_("Cache cleared (%1 files)"), tostring(n)))
                    else
                        infoToast(_("Cache cleared"))
                    end
                else
                    infoToast(T(_("Clear cache failed: %1"),
                        data.error or _("unknown")), true)
                end
            end)
        end,
    })
end

------------------------------------------------------------------------------
-- Menu integration
------------------------------------------------------------------------------

function HIDPassthrough:onDispatcherRegisterActions()

    Dispatcher:registerAction("hidpassthrough_start", {
        category = "none",
        event    = "HIDPassthroughStart",
        title    = _("HID Passthrough: Start daemon"),
        general  = true,
    })
    Dispatcher:registerAction("hidpassthrough_stop", {
        category = "none",
        event    = "HIDPassthroughStop",
        title    = _("HID Passthrough: Stop daemon"),
        general  = true,
    })
    Dispatcher:registerAction("hidpassthrough_toggle", {
        category = "none",
        event    = "HIDPassthroughToggle",
        title    = _("HID Passthrough: Toggle daemon"),
        general  = true,
    })

    -- Upstream only ships "Turn pages", a spinner. These are the fixed steps.
    Dispatcher:registerAction("hidpassthrough_next_page", {
        category = "none",
        event    = "GotoViewRel",
        arg      = 1,
        title    = _("Next page"),
        reader   = true,
    })
    Dispatcher:registerAction("hidpassthrough_prev_page", {
        category = "none",
        event    = "GotoViewRel",
        arg      = -1,
        title    = _("Previous page"),
        reader   = true,
    })

    Dispatcher:registerAction("hidpassthrough_close", {
        category = "none",
        event    = "HIDPassthroughClose",
        title    = _("Close menu or dialog"),
        general  = true,
    })
end

-- Stops one short of ReaderUI/FileManager, whose onClose exits the book.
function HIDPassthrough:onHIDPassthroughClose()
    local target, reached_base
    for widget in UIManager:topdown_widgets_iter() do
        if widget == self.ui then
            reached_base = true
            break
        end
        if not target and not widget.toast and not widget.invisible then
            target = widget
        end
    end
    if not target or not reached_base then return true end

    -- Deferred: we're inside UIManager's walk down the stack we're mutating.
    UIManager:nextTick(function()
        if not UIManager:isWidgetShown(target) then return end
        if target.onClose then
            target:onClose()
        else
            UIManager:close(target)
        end
    end)
    return true
end

-- start() can block up to 15s, so toast now and do the work next tick.
function HIDPassthrough:_runActionAsync(label, fn)
    UIManager:show(InfoMessage:new{
        text = label,
        timeout = 1,
    })
    UIManager:nextTick(function()
        local ok, msg = fn(self)
        UIManager:show(InfoMessage:new{
            text = msg,
            timeout = ok and 2 or 4,
        })
    end)
end

-- true, or UIManager hands these to us again as an active widget.
function HIDPassthrough:onHIDPassthroughStart()
    self:_runActionAsync(_("Starting HID Passthrough daemon…"), self.start)
    return true
end

function HIDPassthrough:onHIDPassthroughStop()
    self:_runActionAsync(_("Stopping HID Passthrough daemon…"), self.stop)
    return true
end

function HIDPassthrough:onHIDPassthroughToggle()
    local label = self:isRunning()
        and _("Stopping HID Passthrough daemon…")
        or  _("Starting HID Passthrough daemon…")
    self:_runActionAsync(label, self.toggle)
    return true
end

-- AutoSuspend is the only thing re-arming powerd's t1 timeout, and it can be off (#136).
local T1_RESET_INTERVAL = 4 * 60
local last_t1_reset = nil

function HIDPassthrough:onInputEvent()
    if not PowerD.resetT1Timeout or PluginShare.keepalive then return end
    if PowerD:isCharging() and not PowerD:isCharged() then return end

    local now = UIManager:getElapsedTimeSinceBoot()
    if last_t1_reset and time.to_number(now - last_t1_reset) < T1_RESET_INTERVAL then
        return
    end
    last_t1_reset = now
    logger.dbg("HIDPassthrough: re-armed powerd's t1 timeout")
    PowerD:resetT1Timeout()
end

function HIDPassthrough:init()
    self:onDispatcherRegisterActions()
    self.ui.menu:registerToMainMenu(self)
    self:_extendEventMap()
    -- Or no binding fires while a menu covers us. Same trick as Screenshoter.
    if self.ui.active_widgets then
        table.insert(self.ui.active_widgets, self)
    end
    UIManager.event_hook:registerWidget("InputEvent", self)
    -- A device may already be connected.
    self:_scanInputs()
    self:_startBatteryPoll()
end

function HIDPassthrough:onCloseWidget()
    self:_cancelPolls()
    self:_stopBatteryPoll()
end

------------------------------------------------------------------------------
-- Peripheral battery in the status bars
------------------------------------------------------------------------------

-- One failed poll per KOReader run is enough to learn the daemon is down.
-- Module level, so reopening a book doesn't stall on the socket again.
local battery_unavailable = false

HIDPassthrough.BATTERY_POLL_INTERVAL = 300
HIDPassthrough.BATTERY_FIRST_POLL = 2
HIDPassthrough.BATTERY_LETTER = "BT"

-- Lowest level among connected devices that report one, or nil for none.
local function lowestBattery(data)
    local lowest
    if data and type(data.connections) == "table" then
        for _, conn in ipairs(data.connections) do
            local level = conn.battery_level
            if type(level) == "number" and (not lowest or level < lowest) then
                lowest = level
            end
        end
    end
    return lowest
end

function HIDPassthrough:_batteryText()
    local level = self._battery
    if not level then return end
    local footer = self.ui.view and self.ui.view.footer
    local prefix = footer and footer.settings and footer.settings.item_prefix
    if prefix == "icons" or prefix == "compact_items" then
        -- Same per-decile glyphs the footer uses for the Kindle's own battery.
        local symbol = PowerD:getBatterySymbol(false, false, level)
        local gap = prefix == "icons" and " " or ""
        return self.BATTERY_LETTER .. symbol .. gap .. level .. "%"
    end
    return self.BATTERY_LETTER .. ": " .. level .. "%"
end

-- Registering flips the footer's "External content" item on, so only do it
-- once a device has actually reported a level.
function HIDPassthrough:_setBatteryShown(shown)
    if shown == self._battery_shown then return end
    self._battery_shown = shown
    local footer = self.ui.view and self.ui.view.footer
    if footer then
        if shown then
            footer:addAdditionalFooterContent(self._battery_content_func)
        else
            footer:removeAdditionalFooterContent(self._battery_content_func)
        end
    end
    if self.ui.crelistener then
        if shown then
            self.ui.crelistener:addAdditionalHeaderContent(self._battery_content_func)
        else
            self.ui.crelistener:removeAdditionalHeaderContent(self._battery_content_func)
        end
    end
end

function HIDPassthrough:_pollBattery()
    local data, err = self:_httpGetJson("/status")
    if not data then
        logger.dbg("HIDPassthrough: battery poll failed,", err)
        battery_unavailable = true
        self._battery = nil
        self:_setBatteryShown(false)
        self._battery_poll_cb = nil
        return
    end

    local level = lowestBattery(data)
    logger.dbg("HIDPassthrough: battery poll ->", tostring(level))
    if level ~= self._battery then
        self._battery = level
        self:_setBatteryShown(level ~= nil)
        UIManager:broadcastEvent(Event:new("RefreshAdditionalContent"))
        if self.ui.crelistener then
            UIManager:broadcastEvent(Event:new("UpdateHeader"))
        end
    end
    UIManager:scheduleIn(self.BATTERY_POLL_INTERVAL, self._battery_poll_cb)
end

function HIDPassthrough:_startBatteryPoll()
    if self._battery_poll_cb or battery_unavailable then return end
    -- Only the reader instance has status bars to draw into.
    if not self.ui.view then return end
    self._battery_content_func = function() return self:_batteryText() end
    self._battery_poll_cb = function() self:_pollBattery() end
    UIManager:scheduleIn(self.BATTERY_FIRST_POLL, self._battery_poll_cb)
end

function HIDPassthrough:_stopBatteryPoll()
    if self._battery_poll_cb then
        UIManager:unschedule(self._battery_poll_cb)
        self._battery_poll_cb = nil
    end
    self:_setBatteryShown(false)
    self._battery = nil
end

function HIDPassthrough:_doToggle(touchmenu_instance)
    local ok, msg = self:toggle()
    UIManager:show(InfoMessage:new{
        text = msg,
        timeout = ok and 2 or 4,
    })
    if touchmenu_instance then
        touchmenu_instance:updateItems()
    end
end

function HIDPassthrough:_doToggleAudio(touchmenu_instance)
    local want = not self:audioEnabled()
    local ok, err = self:setAudioEnabled(want)
    local msg
    if ok then
        msg = want and _("Bluetooth audio on.") or _("Bluetooth audio off.")
    else
        msg = T(_("Could not change it: %1"), tostring(err or "failed"))
    end
    UIManager:show(InfoMessage:new{ text = msg, timeout = ok and 2 or 4 })
    if touchmenu_instance then
        touchmenu_instance:updateItems()
    end
end

function HIDPassthrough:addToMainMenu(menu_items)
    menu_items.hid_passthrough = {
        text = _("BT Manager - HID Passthrough"),
        -- Land in Settings → Network alongside SSH.
        sorting_hint = "network",
        -- Top-level checked state mirrors the daemon, so users can see at
        -- a glance from the Network menu whether it's up.
        checked_func = function() return self:isRunning() end,
        -- Long-press the parent entry to toggle without descending.
        hold_callback = function(touchmenu_instance)
            self:_doToggle(touchmenu_instance)
        end,
        sub_item_table = {
            {
                text = _("HID Passthrough daemon"),
                checked_func = function() return self:isRunning() end,
                check_callback_updates_menu = true,
                callback = function(touchmenu_instance)
                    self:_doToggle(touchmenu_instance)
                end,
            },
            {
                text = _("Bluetooth audio"),
                help_text = _("Sends what the Kindle plays to the paired headphones. While on, the stock audio daemon is replaced; leave it off if audio misbehaves on this device."),
                enabled_func = function() return self:isRunning() end,
                checked_func = function() return self:audioEnabled() end,
                check_callback_updates_menu = true,
                callback = function(touchmenu_instance)
                    self:_doToggleAudio(touchmenu_instance)
                end,
                separator = true,
            },
            {
                text = _("Scan for devices"),
                enabled_func = function() return self:isRunning() end,
                keep_menu_open = true,
                callback = function() self:scanForDevices() end,
                separator = true,
            },
            {
                text = _("Paired devices"),
                enabled_func = function() return self:isRunning() end,
                keep_menu_open = true,
                callback = function() self:showPairedDevices() end,
            },
            {
                text = _("Key mappings"),
                keep_menu_open = true,
                sub_item_table_func = function() return self:genMapperMenu() end,
                separator = true,
            },
            {
                text = _("Debug"),
                separator = true,
                sub_item_table = {
                    {
                        text = _("Show daemon status"),
                        keep_menu_open = true,
                        callback = function() self:showInfo() end,
                    },
                    {
                        text = _("Recent logs"),
                        keep_menu_open = true,
                        callback = function() self:showLogs() end,
                    },
                    {
                        text = _("Input diagnostics"),
                        keep_menu_open = true,
                        callback = function() self:showInputDiagnostics() end,
                    },
                    {
                        text = _("Clear descriptor cache"),
                        enabled_func = function() return self:isRunning() end,
                        keep_menu_open = true,
                        callback = function() self:clearCache() end,
                    },
                },
            },
            {
                text = _("About HID Passthrough"),
                keep_menu_open = true,
                callback = function()
                    UIManager:show(InfoMessage:new{
                        text = T(_([[Pairing runs on the kindle-hid-passthrough Bluetooth HID daemon,
key mappings run on kindle-button-mapper. Both must already be installed.

HID daemon: %1
API:        http://%2:%3

Button Mapper: %4
API:           http://%5:%6

https://github.com/zampierilucas/kindle-hid-passthrough
https://github.com/zampierilucas/kindle-button-mapper-rs]]),
                            self.DAEMON_BINARY,
                            self.API_HOST,
                            tostring(self.API_PORT),
                            self:_mapper().BIN,
                            self:_mapper().HOST,
                            tostring(self:_mapper().PORT)),
                    })
                end,
            },
        },
    }
end

return HIDPassthrough
