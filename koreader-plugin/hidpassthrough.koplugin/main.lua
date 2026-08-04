--[[--
Manage the kindle-hid-passthrough daemon and map keys from inside KOReader.

@module koplugin.hidpassthrough
--]]

local ConfirmBox = require("ui/widget/confirmbox")
local DataStorage = require("datastorage")
local Device = require("device")
local Dispatcher = require("dispatcher")
local InfoMessage = require("ui/widget/infomessage")
local InputContainer = require("ui/widget/container/inputcontainer")
local LuaSettings = require("luasettings")
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

------------------------------------------------------------------------------
-- Key mappings
------------------------------------------------------------------------------
-- Not built on hotkeys.koplugin: it returns disabled unless hasScreenKB or
-- hasKeyboard, which no modern Kindle sets, and PluginLoader caches that.

local MODIFIER_KEYS = {
    Shift = true, Ctrl = true, Alt = true, Meta = true, Sym = true,
    ScreenKB = true, LCtrl = true, LAlt = true, RAlt = true, LMeta = true,
    RMeta = true, CapsLock = true,
}

-- Fixed order so a given combo always serializes to the same id.
local MOD_ORDER = { "Shift", "Ctrl", "Alt", "Meta", "Sym", "ScreenKB" }

-- Shortcuts, so the common bindings don't mean paging through the full tree.
-- By Dispatcher key, never by title, so renames and translations come free.
local COMMON_ACTIONS = {
    "hidpassthrough_next_page",
    "hidpassthrough_prev_page",
    "hidpassthrough_close",
    "toggle_frontlight",
    "night_mode",
    "show_menu",
    "toc",
    "bookmarks",
    "toggle_bookmark",
    "iterate_rotation",
    "back",
}

-- "F13", "Shift+F13". Reads modifiers off the Key hash, not key.modifiers,
-- which is a live reference to Input's table rather than a snapshot.
local function keyToId(key)
    local parts = {}
    for dummy, mod in ipairs(MOD_ORDER) do -- luacheck: ignore dummy
        if key[mod] then table.insert(parts, mod) end
    end
    table.insert(parts, key.key)
    return table.concat(parts, "+")
end

local function idToSequence(id)
    local seq = {}
    for part in id:gmatch("[^+]+") do table.insert(seq, part) end
    return seq
end

-- Shared across the FileManager and ReaderUI plugin instances.
local keymap_path = ffiutil.joinPath(DataStorage:getSettingsDir(),
    "hidpassthrough_keymap.lua")
local keymap_settings

local function getKeymapSettings()
    if not keymap_settings then
        keymap_settings = LuaSettings:open(keymap_path)
    end
    return keymap_settings
end

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
    if Device.input.opened_devices[path] and not input_fds[path] then return end

    local info = checkKeyDevice(path)
    if not info then return end

    -- uhid recreates the node on reconnect; a stale fd makes the input poll
    -- fail with ENODEV and then nothing reaches any plugin.
    if input_fds[info.path] then
        pcall(Device.input.close, Device.input, info.path)
        input_fds[info.path] = nil
    end

    input_fds[info.path] = Device.input:fdopen(info.fd, info.path, info.name)
    logger.info("HIDPassthrough: attached input", info.name, "@", info.path)
    -- Bindings may have been registered before the device showed up.
    self:_extendEventMap()
    self:registerKeyEvents()
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

function HIDPassthrough:registerKeyEvents()
    self.key_events = {}
    local keymap = getKeymapSettings().data
    -- Register every id, even unassigned: the action is resolved at press
    -- time, so edits take effect without re-registering.
    for id in pairs(keymap) do
        self.key_events["HIDPassthroughKey_" .. id] = {
            idToSequence(id),
            event = "HIDPassthroughKeyAction",
            args = id,
        }
    end
    logger.dbg("HIDPassthrough: registered",
        util.tableSize(self.key_events), "key bindings")
end

function HIDPassthrough:onPhysicalKeyboardConnected()
    self:_extendEventMap()
    self:registerKeyEvents()
end

-- Overrides InputContainer's handler, which drops key_events outright.
function HIDPassthrough:onPhysicalKeyboardDisconnected()
    self:_extendEventMap()
    if Device:hasKeys() or next(input_fds) ~= nil then
        self:registerKeyEvents()
    else
        self.key_events = {}
    end
end

function HIDPassthrough:onHIDPassthroughKeyAction(id)
    local actions = getKeymapSettings().data[id]
    if type(actions) ~= "table" or next(actions) == nil then return end
    logger.dbg("HIDPassthrough: executing binding for", id)
    Dispatcher:execute(actions)
    return true
end

-- Overriding onKeyPress bypasses key_events matching, so unbound keys are
-- visible here.
local KeyCapture = InfoMessage:extend{
    on_key_captured = nil,
}

function KeyCapture:onKeyPress(key)
    if MODIFIER_KEYS[key.key] then return true end
    -- Serialize before closing.
    local id = keyToId(key)
    local callback = self.on_key_captured
    UIManager:close(self)
    if callback then callback(id) end
    return true
end

function HIDPassthrough:captureKey(callback)
    UIManager:show(KeyCapture:new{
        text = _("Press the key you want to map.\n\nTap the screen to cancel."),
        on_key_captured = callback,
    })
end

function HIDPassthrough:genKeymapMenu()
    local keymap = getKeymapSettings().data
    local items = {
        {
            text = _("Add a key…"),
            keep_menu_open = true,
            callback = function(touchmenu_instance)
                self:captureKey(function(id)
                    if keymap[id] == nil then
                        keymap[id] = {}
                        self.updated = true
                        self:registerKeyEvents()
                    end
                    -- updateItems() re-renders the cached item_table and
                    -- doesn't re-run sub_item_table_func.
                    if touchmenu_instance then
                        touchmenu_instance.item_table = self:genKeymapMenu()
                        touchmenu_instance:updateItems()
                    end
                    UIManager:show(InfoMessage:new{
                        text = T(_("Bound %1. Pick an action for it below."), id),
                        timeout = 3,
                    })
                end)
            end,
            separator = true,
        },
    }

    local ids = {}
    for id in pairs(keymap) do table.insert(ids, id) end
    table.sort(ids)

    -- Not `for _, id`: that shadows the gettext `_` in these closures.
    for dummy, id in ipairs(ids) do -- luacheck: ignore dummy
        table.insert(items, {
            text_func = function()
                local actions = keymap[id]
                local label = (actions and next(actions) ~= nil)
                    and Dispatcher:menuTextFunc(actions)
                    or _("No action")
                return T("%1  →  %2", id, label)
            end,
            -- On demand: each is the full Dispatcher tree.
            sub_item_table_func = function() return self:genKeyActionMenu(id) end,
            -- Also at the bottom of the action tree, but that's two pages in.
            hold_callback = function(touchmenu_instance)
                UIManager:show(ConfirmBox:new{
                    text = T(_("Remove the mapping for %1?"), id),
                    ok_text = _("Remove"),
                    ok_callback = function()
                        self:removeKey(id)
                        if touchmenu_instance then
                            touchmenu_instance.item_table = self:genKeymapMenu()
                            touchmenu_instance:updateItems()
                        end
                    end,
                })
            end,
            ignored_by_menu_search = true,
        })
    end

    if #ids == 0 then
        table.insert(items, {
            text = _("(no keys mapped yet)"),
            enabled = false,
        })
    end

    -- Used by TouchMenu:backToUpperMenu when a child marks us stale.
    items.refresh_func = function() return self:genKeymapMenu() end
    return items
end

function HIDPassthrough:removeKey(id)
    getKeymapSettings().data[id] = nil
    self.updated = true
    self:registerKeyEvents()
end

function HIDPassthrough:genKeyActionMenu(id)
    local keymap = getKeymapSettings().data
    local sub_items = {}

    local unknown = _("Unknown item")
    for dummy, action in ipairs(COMMON_ACTIONS) do -- luacheck: ignore dummy
        local title = Dispatcher:getNameFromItem(action, nil, true)
        if title ~= unknown then
            table.insert(sub_items, {
                text = title,
                checked_func = function()
                    return keymap[id] ~= nil and keymap[id][action] ~= nil
                end,
                callback = function(touchmenu_instance)
                    if keymap[id] == nil then keymap[id] = {} end
                    if keymap[id][action] == nil then
                        keymap[id][action] = true
                        Dispatcher._addToOrder(keymap, id, action)
                    else
                        keymap[id][action] = nil
                        Dispatcher._removeFromOrder(keymap, id, action)
                    end
                    self.updated = true
                    if touchmenu_instance then
                        touchmenu_instance:updateItems()
                    end
                end,
            })
        end
    end
    if #sub_items > 0 then
        sub_items[#sub_items].separator = true
    end

    Dispatcher:addSubMenu(self, sub_items, keymap, id)
    table.insert(sub_items, {
        text = _("Remove this key"),
        -- Or TouchMenu closes the menu after the callback, undoing our
        -- backToUpperMenu.
        keep_menu_open = true,
        callback = function(touchmenu_instance)
            self:removeKey(id)
            if touchmenu_instance then
                -- Mark stale so backToUpperMenu rebuilds via refresh_func.
                local stack = touchmenu_instance.item_table_stack
                local parent = stack and stack[#stack]
                if parent then parent.needs_refresh = true end
                touchmenu_instance:backToUpperMenu()
            end
        end,
    })
    return sub_items
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

function HIDPassthrough:genMapperDeviceMenu(dev)
    local mapper = self:_mapper()
    local items = {
        {
            text = _("Map a button…"),
            keep_menu_open = true,
            callback = function() self:mapperCapture(dev) end,
            separator = true,
        },
    }

    local text = mapper.getConfig() or ""
    for dummy, kind in ipairs(MAPPER_KINDS) do -- luacheck: ignore dummy
        local section = "device." .. dev.id .. "." .. kind.section
        for dummy2, entry in ipairs(mapper.sectionKeys(text, section)) do -- luacheck: ignore dummy2
            -- The script path is noise, show "koreader.sh next_page".
            local action = entry.value:match("([^/]+)$") or entry.value
            table.insert(items, {
                text = T("%1 %2  →  %3", kind.label, entry.key, action),
                keep_menu_open = true,
                hold_callback = function(touchmenu_instance)
                    UIManager:show(ConfirmBox:new{
                        text = T(_("Remove the mapping for %1 %2?"), kind.label, entry.key),
                        ok_text = _("Remove"),
                        ok_callback = function()
                            self:mapperEdit(function(cur)
                                return mapper.removeKey(cur, section, entry.key)
                            end)
                            if touchmenu_instance then
                                touchmenu_instance.item_table = self:genMapperDeviceMenu(dev)
                                touchmenu_instance:updateItems()
                            end
                        end,
                    })
                end,
                ignored_by_menu_search = true,
            })
        end
    end

    if #items == 1 then
        table.insert(items, {
            text = _("(defaults active — map a button to customize)"),
            enabled = false,
        })
    end
    items.refresh_func = function() return self:genMapperDeviceMenu(dev) end
    return items
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

function HIDPassthrough:mapperCapture(dev)
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
    -- or the helper's timeout.
    UIManager:scheduleIn(0.1, function()
        local cap, err = mapper.capture(node, 8000)
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
        self:mapperPickAction(section, key, label)
    end)
end

function HIDPassthrough:mapperPickAction(section, key, label)
    local mapper = self:_mapper()
    local actions = mapper.actions()
    if not actions then
        UIManager:show(InfoMessage:new{ text = _("Could not fetch the action list.") })
        return
    end

    local menu
    local items = {}
    for dummy, action in ipairs(actions) do -- luacheck: ignore dummy
        table.insert(items, {
            text = T("%1  (%2)", action.label, action.kind),
            callback = function()
                UIManager:close(menu)
                if self:mapperEdit(function(cur)
                    return mapper.setKey(cur, section, key, mapper.actionScript(action))
                end) then
                    UIManager:show(InfoMessage:new{
                        text = T(_("Mapped %1 to %2."), label, action.label),
                        timeout = 3,
                    })
                end
            end,
        })
    end

    menu = Menu:new{
        title = T(_("Action for %1"), label),
        item_table = items,
        width = Screen:getWidth(),
        height = Screen:getHeight(),
        is_popout = false,
        onClose = function() UIManager:close(menu) end,
    }
    UIManager:show(menu)
end

function HIDPassthrough:onFlushSettings()
    if self.updated then
        getKeymapSettings():flush()
        self.updated = false
    end
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
        "(setsid %s --daemon </dev/null >/dev/null 2>&1 &) 2>/dev/null || "
        .. "(%s --daemon </dev/null >/dev/null 2>&1 &)",
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

        local connected = extractField(body, "connected_device")
        if connected and connected ~= "" and connected ~= "null" then
            table.insert(lines, T(_("Connected: %1"), connected))
        end

        if body:find('"scanning"%s*:%s*true') then
            table.insert(lines, _("Currently scanning…"))
        end
        if body:find('"pairing"%s*:%s*true') then
            table.insert(lines, _("Currently pairing…"))
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

    local connected_addr = data.connected_device
    local items = {}
    for _, dev in ipairs(devices) do
        local is_conn = connected_addr
            and dev.address
            and dev.address:upper() == tostring(connected_addr):upper()
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
    self:registerKeyEvents()
    -- Or no binding fires while a menu covers us. Same trick as Screenshoter.
    if self.ui.active_widgets then
        table.insert(self.ui.active_widgets, self)
    end
    UIManager.event_hook:registerWidget("InputEvent", self)
    -- A device may already be connected.
    self:_scanInputs()
end

function HIDPassthrough:onCloseWidget()
    self:_cancelPolls()
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
                sub_item_table_func = function() return self:genKeymapMenu() end,
            },
            {
                text = _("Button mappings (gamepads)"),
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
                        text = T(_([[Manages the kindle-hid-passthrough Bluetooth HID daemon.

Binary: %1
API:    http://%2:%3

The daemon must already be installed on the device. See:
https://github.com/zampierilucas/kindle-hid-passthrough]]),
                            self.DAEMON_BINARY,
                            self.API_HOST,
                            tostring(self.API_PORT)),
                    })
                end,
            },
        },
    }
end

return HIDPassthrough
