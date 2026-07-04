--[[--
HID Passthrough daemon manager.

Adds a "HID Passthrough" entry to Settings → Network that lets the user
start, stop, and check the status of the kindle-hid-passthrough daemon
(https://github.com/zampierilucas/kindle-hid-passthrough) without leaving
KOReader.

The daemon exposes a small HTTP API on http://localhost:8321 (the same one
used by the BTManager WAF app). When it's running, we use that API for
status and to stop it. When it's not running, the API is unreachable, so
starting is done by spawning the binary directly with `--daemon`.

@module koplugin.hidpassthrough
--]]

local ConfirmBox = require("ui/widget/confirmbox")
local Device = require("device")
local Dispatcher = require("dispatcher")
local Event = require("ui/event")
local InfoMessage = require("ui/widget/infomessage")
local InputText = require("ui/widget/inputtext")
local Menu = require("ui/widget/menu")
local Screen = require("device").screen
local TextViewer = require("ui/widget/textviewer")
local UIManager = require("ui/uimanager")
local WidgetContainer = require("ui/widget/container/widgetcontainer")
local lfs = require("libs/libkoreader-lfs")
local logger = require("logger")
local rapidjson = require("rapidjson")
local util = require("util")
local ffiutil = require("ffi/util")
local _ = require("gettext")
local T = require("ffi/util").template

local socket = require("socket")
local http = require("socket.http")
local ltn12 = require("ltn12")

local ffi = require("ffi")
local C = ffi.C
local bit = require("bit")
pcall(require, "ffi/posix_h")
pcall(require, "ffi/fbink_input_h")

local HIDPassthrough = WidgetContainer:extend{
    name = "hidpassthrough",
    is_doc_only = false,

    -- Defaults matching the upstream project layout. Override in
    -- settings/hidpassthrough.lua if your install lives elsewhere.
    DAEMON_BINARY = "/mnt/us/kindle_hid_passthrough/kindle-hid-passthrough",
    DAEMON_RUNNER = "/mnt/us/kindle_hid_passthrough/scripts/run-daemon-pw4.sh",
    DAEMON_CONTROL = "/mnt/us/kindle_hid_passthrough/scripts/hid-passthrough-daemon.sh",
    API_HOST      = "127.0.0.1",
    API_PORT      = 8321,
    API_TIMEOUT   = 2, -- seconds
}

------------------------------------------------------------------------------
-- HTTP helper
------------------------------------------------------------------------------

-- Tiny GET that returns the response body or (nil, err). We don't pull in a
-- JSON parser; we just look for substrings, since the daemon's responses are
-- short and well-known.
function HIDPassthrough:_httpGet(path)
    local url = string.format("http://%s:%d%s", self.API_HOST, self.API_PORT, path)
    local body_chunks = {}

    -- Per-request timeout. socket.http.TIMEOUT is module-global, so save
    -- and restore it to avoid bleeding into the rest of KOReader.
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
--
-- kindle-hid-passthrough is two-tier:
--
--   * An always-on HTTP API server (port 8321) that survives between HID
--     sessions and reports status / accepts /start and /stop commands.
--   * The actual HID daemon, which the API server starts and stops on
--     demand. Its state is reported in `daemon_running` from /status.
--
-- Spawning the binary directly (`kindle-hid-passthrough --daemon`) starts
-- *both* layers in one go.
--
-- That gives us three states:
--
--   "off"        — API server not reachable. Nothing is running. To turn on,
--                  spawn the binary; this brings up both layers.
--   "api_only"   — API server up, HID daemon off. To turn on, POST /start.
--   "on"         — Both layers running. To turn off, POST /stop (leaves the
--                  API server alive, matching what BTManager does).
--
-- The user-facing checkmark is true only for "on".

-- How long to wait for the daemon to come up before giving up. On some
-- Broadcom-era Kindles the Python + Bluetooth stack init can take well over
-- 15s after a clean restart, so keep this generous to avoid false failures.
HIDPassthrough.START_TIMEOUT = 30
HIDPassthrough.STOP_TIMEOUT = 5
HIDPassthrough.REPAIR_TIMEOUT = 15

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

local function statusHasField(body, key)
    if not body then return false end
    local value = body:match('"' .. key .. '"%s*:%s*(%b[])')
    if value then
        return value ~= "[]"
    end
    value = body:match('"' .. key .. '"%s*:%s*"([^"]*)"')
    return value ~= nil and value ~= ""
end

function HIDPassthrough:_statusHasUsableInput(body)
    return statusHasField(body, "uhid_name") or statusHasField(body, "input_paths")
end

function HIDPassthrough:_statusLooksHalfStuck(body)
    if not body then return false end
    if body:find('"scanning"%s*:%s*true') and not body:find('"daemon_running"%s*:%s*true') then
        return true
    end
    if statusHasField(body, "connected_device") and not self:_statusHasUsableInput(body) then
        return true
    end
    return false
end

function HIDPassthrough:_runControl(action)
    if not util.pathExists(self.DAEMON_CONTROL) then
        return false, _("Daemon control script not found.")
    end
    local cmd = string.format("%s %s >/dev/null 2>&1", self.DAEMON_CONTROL, action)
    logger.info("HIDPassthrough: control script:", cmd)
    os.execute(cmd)
    return true
end

function HIDPassthrough:_runControlDetached(action)
    if not util.pathExists(self.DAEMON_CONTROL) then
        return false, _("Daemon control script not found.")
    end
    local cmd = string.format(
        "(setsid sh -c '%s %s >/dev/null 2>&1' </dev/null >/dev/null 2>&1 &) 2>/dev/null || "
        .. "(sh -c '%s %s >/dev/null 2>&1' </dev/null >/dev/null 2>&1 &)",
        self.DAEMON_CONTROL, action,
        self.DAEMON_CONTROL, action
    )
    logger.info("HIDPassthrough: detached control script:", cmd)
    os.execute(cmd)
    return true
end

function HIDPassthrough:_runShellDetached(shell_cmd)
    local cmd = string.format(
        "(setsid sh -c '%s' </dev/null >/dev/null 2>&1 &) 2>/dev/null || "
        .. "(sh -c '%s' </dev/null >/dev/null 2>&1 &)",
        shell_cmd, shell_cmd
    )
    logger.info("HIDPassthrough: detached shell command:", cmd)
    os.execute(cmd)
    return true
end

function HIDPassthrough:getStatusData()
    local data, err = self:_httpGetJson("/status")
    if not data then
        return nil, err
    end
    return data, nil
end

function HIDPassthrough:getConnectionState()
    local daemon_state = self:getState()
    if daemon_state == "off" then
        return "daemon_off", nil
    end

    local data, err = self:getStatusData()
    if not data then
        return "idle", nil, err
    end

    if data.pairing then
        return "pairing", data
    end
    if data.scanning then
        return "scanning", data
    end

    local connected = data.connected_device
    if connected ~= nil and connected ~= "" and tostring(connected) ~= "null" then
        return "connected", data
    end

    return "idle", data
end

function HIDPassthrough:_waitForConnectedInput(addr, timeout)
    timeout = timeout or self.REPAIR_TIMEOUT
    for i = 1, timeout do
        ffiutil.sleep(1)
        local data = self:getStatusData()
        if data and data.connected_device and data.connected_device ~= "" then
            local same_addr = (not addr)
                or tostring(data.connected_device):upper() == tostring(addr):upper()
            local has_input = (data.uhid_name and data.uhid_name ~= "")
                or (type(data.input_paths) == "table" and #data.input_paths > 0)
            if same_addr and has_input then
                logger.info("HIDPassthrough: connected keyboard gained input after", i, "ticks")
                return true
            end
        end
    end
    return false
end

function HIDPassthrough:_finishRepair(ok, msg, is_error)
    self._repair_ctx = nil
    if ok then
        infoToast(msg or _("Keyboard input repaired"))
    else
        infoToast(msg or _("Repair failed"), is_error ~= false)
    end
end

function HIDPassthrough:_restartWrapper()
    if self._repair_ctx then
        infoToast(_("Repair already in progress"), true)
        return
    end

    infoToast(_("Restarting daemon wrapper…"))
    self:_cancelPolls()
    self:_stopKeyboardWatcher()
    self._repair_ctx = {
        mode = "wrapper",
    }

    local shell_cmd = table.concat({
        self.DAEMON_CONTROL .. " stop >/dev/null 2>&1 || true",
        "sleep 4",
        self.DAEMON_CONTROL .. " start >/dev/null 2>&1",
    }, "; ")
    local ok, err = self:_runShellDetached(shell_cmd)
    if not ok then
        self:_finishRepair(false, T(_("Wrapper restart failed: %1"), err), true)
        return
    end
    UIManager:scheduleIn(2, function() self:_pollForShellRecovery() end)
end

function HIDPassthrough:_radioResetWrapper()
    if self._repair_ctx then
        infoToast(_("Repair already in progress"), true)
        return
    end

    infoToast(_("Resetting BLE radio (Wi-Fi will be turned off)…"))
    self:_cancelPolls()
    self:_stopKeyboardWatcher()
    self._repair_ctx = {
        mode = "radio",
    }

    local shell_cmd = table.concat({
        "/usr/bin/lipc-set-prop com.lab126.cmd wirelessEnable 0 >/dev/null 2>&1 || true",
        "sleep 3",
        self.DAEMON_CONTROL .. " stop >/dev/null 2>&1 || true",
        "sleep 4",
        self.DAEMON_CONTROL .. " start >/dev/null 2>&1",
    }, "; ")

    local ok, err = self:_runShellDetached(shell_cmd)
    if not ok then
        self:_finishRepair(false, T(_("Radio reset failed: %1"), err), true)
        return
    end

    infoToast(_("BLE radio reset: Wi-Fi off requested. Restarting daemon…"))
    UIManager:scheduleIn(2, function() self:_pollForShellRecovery() end)
end

function HIDPassthrough:_softRepairKeyboardInput(addr, proto)
    if self._repair_ctx then
        infoToast(_("Repair already in progress"), true)
        return
    end
    if not addr or addr == "" then
        infoToast(_("Soft repair needs a connected device."), true)
        return
    end

    infoToast(_("Soft repair: reconnecting keyboard…"))
    self:_cancelPolls()
    self._repair_ctx = {
        addr = addr,
        proto = proto or "ble",
        mode = "soft",
    }

    self:_httpGet("/disconnect?addr=" .. urlEncode(addr))
    UIManager:scheduleIn(1, function()
        if not self._repair_ctx then return end
        self:_startKeyboardWatcher()
        local url = "/connect?addr=" .. urlEncode(addr)
            .. "&protocol=" .. urlEncode(self._repair_ctx.proto)
        local data, cerr = self:_httpGetJson(url)
        if not data then
            self:_finishRepair(false, T(_("Soft repair reconnect error: %1"), tostring(cerr)), true)
            return
        end
        if not data.ok then
            self:_finishRepair(false, T(_("Soft repair failed: %1"), data.error or _("unknown")), true)
            return
        end
        self:_repairPollForInput(addr, self.REPAIR_TIMEOUT)
    end)
end

function HIDPassthrough:_repairPollForState(target, timeout, on_ok, on_fail)
    local tick = 0
    local function poll()
        if not self._repair_ctx then return end
        local state = self:getState()
        if state == target then
            on_ok()
            return
        end
        tick = tick + 1
        if tick >= timeout then
            on_fail()
            return
        end
        UIManager:scheduleIn(1, poll)
    end
    UIManager:scheduleIn(1, poll)
end

function HIDPassthrough:_repairPollForInput(addr, timeout)
    local tick = 0
    local function poll()
        if not self._repair_ctx then return end
        local data = self:getStatusData()
        if data and data.connected_device and data.connected_device ~= "" then
            local same_addr = (not addr)
                or tostring(data.connected_device):upper() == tostring(addr):upper()
            local has_input = (data.uhid_name and data.uhid_name ~= "")
                or (type(data.input_paths) == "table" and #data.input_paths > 0)
            if same_addr and has_input then
                self:_finishRepair(true, _("Keyboard input repaired"))
                return
            end
        end
        tick = tick + 1
        if tick >= timeout then
            self:_finishRepair(false, _("Daemon recovered, but keyboard input is still missing."), true)
            return
        end
        UIManager:scheduleIn(1, poll)
    end
    UIManager:scheduleIn(1, poll)
end

function HIDPassthrough:_repairPollForNotOn(timeout, on_ok, on_fail)
    local tick = 0
    local function poll()
        if not self._repair_ctx then return end
        local state = self:getState()
        if state ~= "on" then
            on_ok(state)
            return
        end
        tick = tick + 1
        if tick >= timeout then
            on_fail()
            return
        end
        UIManager:scheduleIn(1, poll)
    end
    UIManager:scheduleIn(1, poll)
end

function HIDPassthrough:_pollForShellRecovery()
    local tick = 0
    local timeout = self.START_TIMEOUT + 12
    local function poll()
        if not self._repair_ctx then return end
        local state = self:getState()
        if state == "on" then
            self:_startKeyboardWatcher()
            if self._repair_ctx.mode == "radio" then
                self:_finishRepair(true, _("BLE radio reset complete. Wi-Fi remains off."))
            else
                self:_finishRepair(true, _("Daemon wrapper restarted."))
            end
            return
        end
        tick = tick + 1
        if tick >= timeout then
            if self._repair_ctx.mode == "radio" then
                self:_finishRepair(false, _("BLE radio reset did not recover within timeout."), true)
            else
                self:_finishRepair(false, _("Wrapper restart did not recover within timeout."), true)
            end
            return
        end
        UIManager:scheduleIn(1, poll)
    end
    UIManager:scheduleIn(1, poll)
end

function HIDPassthrough:_repairStartPhase()
    if not self._repair_ctx then return end
    local ok, err = self:_runControlDetached("start")
    if not ok then
        self:_finishRepair(false, T(_("Repair failed: %1"), err), true)
        return
    end

    self:_repairPollForState("on", self.START_TIMEOUT, function()
        if not self._repair_ctx then return end
        self:_startKeyboardWatcher()
        local addr = self._repair_ctx.addr
        local proto = self._repair_ctx.proto or "ble"
        local mode = self._repair_ctx.mode
        if not addr or addr == "" then
            if mode == "wrapper" then
                self:_finishRepair(true, _("Daemon wrapper restarted."))
            else
                self:_finishRepair(true, _("Daemon repaired. Reconnect the keyboard once."))
            end
            return
        end
        local url = "/connect?addr=" .. urlEncode(addr)
            .. "&protocol=" .. urlEncode(proto)
        local data, cerr = self:_httpGetJson(url)
        if not data then
            self:_finishRepair(false, T(_("Reconnect error: %1"), tostring(cerr)), true)
            return
        end
        if not data.ok then
            self:_finishRepair(false, T(_("Reconnect failed: %1"), data.error or _("unknown")), true)
            return
        end
        self:_repairPollForInput(addr, self.REPAIR_TIMEOUT)
    end, function()
        self:_finishRepair(false, _("Repair failed: daemon did not come back."), true)
    end)
end

function HIDPassthrough:_repairStopPhase()
    if not self._repair_ctx then return end
    local ok, err = self:_runControlDetached("stop")
    if not ok then
        self:_finishRepair(false, T(_("Repair failed: %1"), err), true)
        return
    end

    self:_repairPollForState("off", self.STOP_TIMEOUT + 3, function()
        self:_repairStartPhase()
    end, function()
        local state = self:getState()
        if state ~= "on" then
            self:_repairStartPhase()
        else
            self:_finishRepair(false, _("Repair failed: daemon would not stop."), true)
        end
    end)
end

------------------------------------------------------------------------------
-- Keyboard wiring
------------------------------------------------------------------------------
-- TODO: Remove uevent handling once koreader/koreader-base#2327 and
-- koreader/koreader#15248 are merged upstream. Once those land, KOReader
-- will natively support uevent-based keyboard hot-plug on Kindle and
-- the polling logic below becomes unnecessary.
--
-- The hard part. Background: KOReader's input layer on Kindle reads from a
-- hardcoded list of /dev/input/event* devices opened at startup. The HID
-- daemon creates a uhid device only when a BLE keyboard actually connects,
-- which can happen long after the daemon started. KOReader's bundled
-- externalkeyboard.koplugin handles exactly this kind of situation, but it
-- self-disables on Kindle (it gates on Kobo USB-OTG sysfs paths and won't
-- even register otherwise — see plugins/externalkeyboard.koplugin/main.lua,
-- the early `return { disabled = true }` block).
--
-- We borrow upstream's actual mechanism — which works regardless of the
-- USB-OTG gating — and apply it from this plugin instead:
--
--   1. Use FBInkInput's fbink_input_check() to ask the kernel "is this path
--      a keyboard?". It returns an already-opened fd if yes.
--   2. Hand that fd to Device.input:fdopen(fd, path, name) — the three-arg
--      form that registers a pre-opened fd. (NOT Input:open(path), which
--      doesn't work for hot-added devices on Kindle: the C backend ends up
--      with a stale entry that fails the next epoll wait with ENODEV. We
--      learned that the hard way.)
--   3. Merge upstream's event_map_keyboard.lua into Device.input.event_map
--      and flip Device.hasKeyboard / hasKeys / hasDPad to truthy stubs, so
--      KOReader treats the new device as a real keyboard (event lookup,
--      input dialogs, focus, etc.). Without this, key codes from the new
--      fd would be silently dropped because the device's event_map has no
--      entries for QWERTY scancodes.
--   4. On removal, undo all of the above.
--
-- Since we can't subscribe to kernel uevents on Kindle the way the upstream
-- plugin does on Kobo, we poll. The polling is cheap: a few ioctls and a
-- directory listing every few seconds, only while the daemon is "on".

HIDPassthrough.WATCHER_INTERVAL = 3 -- seconds

-- Try to load the FBInkInput library. It's part of koreader-base on Kobo
-- and Kindle, but we still wrap it in pcall so the plugin degrades cleanly
-- on platforms where it isn't available — the start/stop UI keeps working.
local FBInkInput
do
    local ok, lib = pcall(function()
        return ffi.loadlib("fbink_input", 1)
    end)
    if ok then
        FBInkInput = lib
    else
        logger.warn("HIDPassthrough: fbink_input not available, keyboard "
            .. "auto-attach disabled:", tostring(lib))
    end
end

-- Stub functions used to flip Device.has* properties on/off.
local function yes() return true end
local function no()  return false end

-- Map of attached keyboard event paths -> { fd_object, original_caps_index }.
-- The fd_object is whatever Device.input:fdopen returns, which we hand back
-- to :close() on removal.
HIDPassthrough._kb_attached = {}
HIDPassthrough._kb_count = 0
HIDPassthrough._kb_original_caps = nil

-- Pull in the upstream keyboard event_map. Prefer the upstream copy (so we
-- get any improvements automatically); fall back to our bundled copy if it
-- isn't there.
function HIDPassthrough:_loadKeyboardEventMap()
    local upstream = "plugins/externalkeyboard.koplugin/event_map_keyboard.lua"
    local f = io.open(upstream, "r")
    if f then
        f:close()
        local ok, map = pcall(dofile, upstream)
        if ok and type(map) == "table" then
            return map
        end
        logger.warn("HIDPassthrough: failed to dofile upstream event_map:", map)
    end
    local bundled = "plugins/hidpassthrough.koplugin/event_map_keyboard.lua"
    local ok, map = pcall(dofile, bundled)
    if ok and type(map) == "table" then
        return map
    end
    logger.warn("HIDPassthrough: failed to dofile bundled event_map:", map)
    return nil
end

-- Snapshot the device-wide input caps so we can restore them when the last
-- keyboard goes away. Idempotent across multiple keyboard connects.
function HIDPassthrough:_snapshotDeviceCaps()
    if self._kb_original_caps then return end
    self._kb_original_caps = {
        event_map       = Device.input.event_map,
        keyboard_layout = Device.keyboard_layout,
        hasKeyboard     = Device.hasKeyboard,
        hasKeys         = Device.hasKeys,
        hasFewKeys      = Device.hasFewKeys,
        hasDPad         = Device.hasDPad,
    }
end

function HIDPassthrough:_restoreDeviceCaps()
    if not self._kb_original_caps then return end
    Device.input.event_map = self._kb_original_caps.event_map
    Device.keyboard_layout = self._kb_original_caps.keyboard_layout
    Device.hasKeyboard     = self._kb_original_caps.hasKeyboard
    Device.hasKeys         = self._kb_original_caps.hasKeys
    Device.hasFewKeys      = self._kb_original_caps.hasFewKeys
    Device.hasDPad         = self._kb_original_caps.hasDPad
    self._kb_original_caps = nil
end

-- Ask FBInkInput whether `path` is a keyboard. Returns a table with fd,
-- path, name, has_dpad on success, or nil if it isn't a keyboard or the
-- check failed. Mirrors upstream externalkeyboard.koplugin's checkKeyboard.
function HIDPassthrough:_checkKeyboard(path)
    if not FBInkInput then return nil end
    local ok, result = pcall(function()
        local dev = FBInkInput.fbink_input_check(path, C.INPUT_KEYBOARD, 0, 0)
        if dev == nil then return nil end
        local r
        if dev.matched then
            r = {
                fd       = tonumber(dev.fd),
                path     = ffi.string(dev.path),
                name     = ffi.string(dev.name),
                has_dpad = bit.band(dev.type, C.INPUT_DPAD) ~= 0,
            }
        end
        C.free(dev)
        return r
    end)
    if not ok then
        logger.dbg("HIDPassthrough: _checkKeyboard error for", path, ":", result)
        return nil
    end
    return result
end

-- List /dev/input/event* paths. Returns nil when the directory can't be
-- enumerated, so callers can tell "no devices" apart from "listing failed".
local function listEventPaths()
    local ok, paths = pcall(function()
        local t = {}
        for name in lfs.dir("/dev/input") do
            if name:match("^event%d+$") then
                table.insert(t, "/dev/input/" .. name)
            end
        end
        return t
    end)
    if not ok then
        logger.dbg("HIDPassthrough: /dev/input listing failed:", paths)
        return nil
    end
    return paths
end

-- Attach a keyboard given a checkKeyboard result. Idempotent: skips if the
-- path is already attached.
function HIDPassthrough:_attachKeyboard(info)
    if self._kb_attached[info.path] then return end

    local ok, fd = pcall(Device.input.fdopen, Device.input,
        info.fd, info.path, info.name)
    if not ok then
        logger.warn("HIDPassthrough: fdopen failed for", info.path, ":", fd)
        return
    end

    self:_snapshotDeviceCaps()

    local event_map = self:_loadKeyboardEventMap()
    if event_map then
        local merged = {}
        util.tableMerge(merged, Device.input.event_map)
        util.tableMerge(merged, event_map)
        Device.input.event_map = merged
    end

    Device.hasKeyboard = yes
    Device.hasKeys     = yes
    Device.hasFewKeys  = no
    if info.has_dpad then
        Device.hasDPad = yes
    end

    self._kb_attached[info.path] = { fd = fd, has_dpad = info.has_dpad }
    self._kb_count = self._kb_count + 1
    logger.info("HIDPassthrough: attached keyboard", info.name, "@", info.path,
        "(total:", self._kb_count, ")")

    if self._kb_count == 1 then
        UIManager:show(InfoMessage:new{
            text = _("Keyboard connected"),
            timeout = 1,
        })
        -- Tell every visible widget that a physical keyboard exists now,
        -- so input fields enable hardware-keyboard handling. This is the
        -- same dance the upstream external keyboard plugin does.
        InputText.initInputEvents()
        UIManager:broadcastEvent(Event:new("PhysicalKeyboardConnected"))
    end
end

-- Detach a keyboard by path. Closes the fd via Input:close, decrements the
-- count, and if it was the last one, restores device caps and broadcasts
-- the disconnect event.
function HIDPassthrough:_detachKeyboard(path)
    local entry = self._kb_attached[path]
    if not entry then return end

    local ok, err = pcall(Device.input.close, Device.input, path)
    if not ok then
        logger.warn("HIDPassthrough: close failed for", path, ":", err)
    end

    self._kb_attached[path] = nil
    self._kb_count = self._kb_count - 1
    logger.info("HIDPassthrough: detached keyboard", path,
        "(remaining:", self._kb_count, ")")

    if self._kb_count == 0 then
        self:_restoreDeviceCaps()
        UIManager:show(InfoMessage:new{
            text = _("Keyboard disconnected"),
            timeout = 1,
        })
        InputText.initInputEvents()
        UIManager:broadcastEvent(Event:new("PhysicalKeyboardDisconnected"))
    end
end

-- TODO: Remove uevent handling once koreader/koreader-base#2327 and
-- koreader/koreader#15248 are merged upstream.
-- One reconciliation pass: check every existing /dev/input/event* against
-- fbink_input_check, attach any that are keyboards we don't know about,
-- and detach any we do know about that have disappeared.
function HIDPassthrough:_reconcileKeyboards()
    if not self._kb_watcher_active then return end
    if not FBInkInput then return end

    local event_paths = listEventPaths()
    if not event_paths then
        -- Listing failed; don't treat that as "all keyboards gone".
        UIManager:scheduleIn(self.WATCHER_INTERVAL, self._reconcileKeyboardsCb)
        return
    end

    local seen = {}
    for _, path in ipairs(event_paths) do
        seen[path] = true
        if not self._kb_attached[path] then
            local info = self:_checkKeyboard(path)
            if info then
                self:_attachKeyboard(info)
            end
        end
    end

    -- Detach anything we have that's no longer present.
    local gone = {}
    for path in pairs(self._kb_attached) do
        if not seen[path] then table.insert(gone, path) end
    end
    for _, path in ipairs(gone) do
        self:_detachKeyboard(path)
    end

    UIManager:scheduleIn(self.WATCHER_INTERVAL, self._reconcileKeyboardsCb)
end

function HIDPassthrough:_startKeyboardWatcher()
    if self._kb_watcher_active then return end
    if not FBInkInput then
        logger.info("HIDPassthrough: keyboard watcher not started "
            .. "(FBInkInput unavailable)")
        return
    end
    self._kb_watcher_active = true
    -- Bind a stable callback so UIManager:unschedule could find it if needed.
    -- We don't actually unschedule by reference (the active flag handles it),
    -- but it keeps the closure allocation out of the hot loop.
    self._reconcileKeyboardsCb = function() self:_reconcileKeyboards() end
    logger.info("HIDPassthrough: starting keyboard watcher")
    UIManager:scheduleIn(1, self._reconcileKeyboardsCb)
end

function HIDPassthrough:_stopKeyboardWatcher()
    if not self._kb_watcher_active then return end
    self._kb_watcher_active = false
    -- Detach everything we have. Snapshot keys first because _detachKeyboard
    -- mutates the table.
    local paths = {}
    for path in pairs(self._kb_attached) do table.insert(paths, path) end
    for _, path in ipairs(paths) do
        self:_detachKeyboard(path)
    end
    logger.info("HIDPassthrough: keyboard watcher stopped")
end

------------------------------------------------------------------------------
-- Start / stop
------------------------------------------------------------------------------

-- Spawn the binary detached. Used only when the API server itself is down.
function HIDPassthrough:_spawnBinary()
    if not util.pathExists(self.DAEMON_BINARY) then
        return false, T(_("Daemon binary not found at %1."), self.DAEMON_BINARY)
    end
    -- Detached background launch via setsid so it survives KOReader exiting.
    -- The exit code of this command is meaningless: the subshell backgrounds
    -- the process and returns immediately.
    local binary = self.DAEMON_RUNNER
    if not util.pathExists(binary) then
        binary = self.DAEMON_BINARY
    end
    local cmd = string.format(
        "(setsid %s </dev/null >/dev/null 2>&1 &) 2>/dev/null || "
        .. "(%s </dev/null >/dev/null 2>&1 &)",
        binary, binary
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
    local state, body = self:getState()

    if state == "on" then
        -- Daemon already running. Still make sure the watcher is going, in
        -- case the user toggled through "on -> off (watcher stops) -> on"
        -- without us knowing about the first transition.
        self:_startKeyboardWatcher()
        return true, _("HID Passthrough daemon is already running.")
    end

    local ok, msg = self:_doStart(state, body)
    if ok then
        self:_startKeyboardWatcher()
    end
    return ok, msg
end

-- The original start logic, factored out so start() can wrap it with input
-- device tracking.
function HIDPassthrough:_doStart(state, body)
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

    -- state == "api_only": usually just ask the API server to start the
    -- daemon. But when the API looks half-stuck, a full wrapper restart is
    -- more reliable than /start.
    if self:_statusLooksHalfStuck(body) and util.pathExists(self.DAEMON_CONTROL) then
        logger.warn("HIDPassthrough: detected half-stuck API state, forcing control-script restart")
        self:_runControlDetached("stop")
        ffiutil.sleep(2)
        self:_runControlDetached("start")
        if self:_waitForState("on", self.START_TIMEOUT) then
            return true, _("HID Passthrough daemon restarted.")
        end
        return false, _("Daemon was restarted, but did not recover within timeout.")
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

    -- Detach keyboards *before* asking the daemon to stop, so the input
    -- read loop doesn't see fds vanish under it. _stopKeyboardWatcher
    -- closes every keyboard fd we own and restores Device caps.
    self:_stopKeyboardWatcher()

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

    -- Some Kindle builds keep the API responsive but fail to tear down the
    -- HID layer via /stop. Fall back to the shell control script, which
    -- forcefully cleans up lingering loader processes when needed.
    if util.pathExists(self.DAEMON_CONTROL) then
        local cmd = string.format("%s stop >/dev/null 2>&1", self.DAEMON_CONTROL)
        logger.warn("HIDPassthrough: /stop timed out, falling back to:", cmd)
        self:_runControlDetached("stop")
        for i = 1, self.STOP_TIMEOUT do
            ffiutil.sleep(1)
            if self:getState() ~= "on" then
                return true, _("HID Passthrough daemon stopped.")
            end
        end
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

function HIDPassthrough:_repairKeyboardInput(addr, proto)
    if self._repair_ctx then
        infoToast(_("Repair already in progress"), true)
        return
    end
    infoToast(_("Full repair started. KOReader may restart."))
    self:_cancelPolls()
    self:_stopKeyboardWatcher()
    self._repair_ctx = {
        addr = addr,
        proto = proto,
        mode = "full",
    }

    if addr and addr ~= "" then
        self:_httpGet("/disconnect?addr=" .. urlEncode(addr))
    end
    UIManager:scheduleIn(1, function() self:_repairStopPhase() end)
end

function HIDPassthrough:toggleConnection()
    local conn_state, data = self:getConnectionState()

    if conn_state == "daemon_off" then
        local ok, msg = self:start()
        if not ok then
            return false, msg
        end
        conn_state, data = self:getConnectionState()
    end

    if conn_state == "scanning" then
        return true, _("Already scanning for HID devices.")
    end
    if conn_state == "pairing" then
        return true, _("Already pairing a HID device.")
    end

    if conn_state == "connected" then
        local addr = data and data.connected_device
        if not addr or addr == "" or tostring(addr) == "null" then
            return false, _("Connected device address unavailable.")
        end
        local res, err = self:_httpGetJson("/disconnect?addr=" .. urlEncode(addr))
        if not res then
            return false, T(_("Disconnect error: %1"), tostring(err))
        end
        if res.ok then
            return true, _("Disconnected")
        end
        return false, T(_("Disconnect failed: %1"), res.error or _("unknown"))
    end

    local devices = data and data.devices or {}
    if #devices == 1 then
        local dev = devices[1]
        local addr = dev and dev.address
        if not addr or addr == "" then
            return false, _("Paired device address unavailable.")
        end
        local url = "/connect?addr=" .. urlEncode(addr)
        local proto = dev.protocol or "ble"
        if proto ~= "" then
            url = url .. "&protocol=" .. urlEncode(proto)
        end
        local res, err = self:_httpGetJson(url)
        if not res then
            return false, T(_("Connect error: %1"), tostring(err))
        end
        if res.ok then
            return true, _("Connect requested")
        end
        return false, T(_("Connect failed: %1"), res.error or _("unknown"))
    end

    if #devices > 1 then
        self:showPairedDevices()
        return true, _("Choose a paired device.")
    end

    self:scanForDevices()
    return true, _("Scanning for HID devices…")
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
        table.insert(items, {
            text = _("Soft repair keyboard"),
            callback = function()
                UIManager:close(self._action_menu)
                self._action_menu = nil
                self:_softRepairKeyboardInput(addr, proto)
            end,
        })
        table.insert(items, {
            text = _("Full repair keyboard"),
            callback = function()
                UIManager:close(self._action_menu)
                self._action_menu = nil
                UIManager:show(ConfirmBox:new{
                    text = _("Full repair restarts the Bluetooth stack and may restart KOReader. Continue?"),
                    ok_text = _("Run full repair"),
                    ok_callback = function()
                        self:_repairKeyboardInput(addr, proto)
                    end,
                })
            end,
        })
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
    if not is_connected then
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
    end

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
        title = _("HID Passthrough Logs"),
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
    -- These show up in the gesture manager under "General" category, so the
    -- user can bind any of them to corner taps, swipes, multiswipes, or
    -- physical buttons.
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
end

-- Run a start/stop/toggle action triggered by a gesture. We can't call the
-- blocking methods directly from the dispatcher's callback because start()
-- can wait up to 15 seconds for the daemon to come up, which would freeze
-- the UI mid-gesture. So we show an immediate toast acknowledging the
-- action and defer the real work to the next UI tick.
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

function HIDPassthrough:onHIDPassthroughStart()
    self:_runActionAsync(_("Starting HID Passthrough daemon…"), self.start)
end

function HIDPassthrough:onHIDPassthroughStop()
    self:_runActionAsync(_("Stopping HID Passthrough daemon…"), self.stop)
end

function HIDPassthrough:onHIDPassthroughToggle()
    local label = self:isRunning()
        and _("Stopping HID Passthrough daemon…")
        or  _("Starting HID Passthrough daemon…")
    self:_runActionAsync(label, self.toggle)
end

function HIDPassthrough:init()
    self:onDispatcherRegisterActions()
    self.ui.menu:registerToMainMenu(self)

    -- The daemon may already be running from a previous session (upstart,
    -- kterm, or a leftover API server from an earlier KOReader run). If so,
    -- kick the watcher so any keyboard connected later gets picked up. We
    -- defer the HTTP probe to avoid blocking plugin init.
    UIManager:scheduleIn(2, function()
        if self:isRunning() then
            logger.info("HIDPassthrough: daemon already running on init, "
                .. "starting keyboard watcher")
            self:_startKeyboardWatcher()
        end
    end)
end

-- Called when KOReader tears down. Leave the daemon running (the API server
-- is designed to outlive client UIs, and you may well want it up for the
-- next session), but cancel our scheduled tasks and detach our fds so we
-- don't leave KOReader polling vanishing devices on the way out.
function HIDPassthrough:onCloseWidget()
    if self._kb_watcher_active then
        logger.info("HIDPassthrough: KOReader closing, stopping keyboard watcher")
        self:_stopKeyboardWatcher()
    end
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
        text = _("HID Passthrough"),
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
                text = _("Start daemon"),
                enabled_func = function() return not self:isRunning() end,
                keep_menu_open = true,
                callback = function(touchmenu_instance)
                    local ok, msg = self:start()
                    UIManager:show(InfoMessage:new{
                        text = msg,
                        timeout = ok and 2 or 4,
                    })
                    if touchmenu_instance then
                        touchmenu_instance:updateItems()
                    end
                end,
            },
            {
                text = _("Stop daemon"),
                enabled_func = function() return self:isRunning() end,
                keep_menu_open = true,
                callback = function(touchmenu_instance)
                    local ok, msg = self:stop()
                    UIManager:show(InfoMessage:new{
                        text = msg,
                        timeout = ok and 2 or 4,
                    })
                    if touchmenu_instance then
                        touchmenu_instance:updateItems()
                    end
                end,
            },
            {
                text = _("Restart daemon wrapper"),
                keep_menu_open = true,
                callback = function()
                    UIManager:show(ConfirmBox:new{
                        text = _("Restart the HID wrapper using the same stop/start sequence as the working SSH recovery?"),
                        ok_text = _("Restart wrapper"),
                        ok_callback = function()
                            self:_restartWrapper()
                        end,
                    })
                end,
            },
            {
                text = _("Radio reset for BLE"),
                keep_menu_open = true,
                callback = function()
                    UIManager:show(ConfirmBox:new{
                        text = _("Turn Wi-Fi off, then restart the HID wrapper? Use this when BLE is stuck on HCI reset timeouts. Wi-Fi will remain off."),
                        ok_text = _("Reset radio"),
                        ok_callback = function()
                            self:_radioResetWrapper()
                        end,
                    })
                end,
                separator = true,
            },
            {
                text = _("Scan for devices"),
                enabled_func = function() return self:isRunning() end,
                keep_menu_open = true,
                callback = function() self:scanForDevices() end,
            },
            {
                text = _("Paired devices"),
                enabled_func = function() return self:isRunning() end,
                keep_menu_open = true,
                callback = function() self:showPairedDevices() end,
            },
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
                text = _("Clear descriptor cache"),
                enabled_func = function() return self:isRunning() end,
                keep_menu_open = true,
                callback = function() self:clearCache() end,
                separator = true,
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
