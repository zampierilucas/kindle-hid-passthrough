--[[--
Client for the kindle-button-mapper WAF helper API on 127.0.0.1:8322.

The helper is the same process the MapperManager app talks to; it is spawned
on demand with the same pidfile, so whichever frontend gets there first owns
it. Config edits are line-based on the ini text, the file is hand-edited and
a parser round-trip would eat comments.
--]]

local M = {
    BIN     = "/mnt/us/kindle-button-mapper/kindle-button-mapper",
    CONFIG  = "/mnt/us/kindle-button-mapper/config.ini",
    SCRIPTS = "/mnt/us/kindle-button-mapper/scripts",
    MEDIA   = "/mnt/us/kindle_hid_passthrough/assets/audio-hack/media.sh",
    PIDFILE = "/tmp/kindle-button-mapper-waf.pid",
    LOG     = "/var/log/kindle-button-mapper-waf.log",
    HOST    = "127.0.0.1",
    PORT    = 8322,
    TIMEOUT = 3, -- seconds; capture calls pass their own
}

------------------------------------------------------------------------------
-- Transport (requires KOReader's socket libs, loaded lazily so the pure
-- config functions below stay testable under plain luajit)
------------------------------------------------------------------------------

local function request(method, path, body, timeout)
    local socket = require("socket")
    local http = require("socket.http")
    local ltn12 = require("ltn12")

    timeout = timeout or M.TIMEOUT
    local chunks = {}
    local saved = http.TIMEOUT
    http.TIMEOUT = timeout
    local req = {
        url = string.format("http://%s:%d%s", M.HOST, M.PORT, path),
        method = method,
        sink = ltn12.sink.table(chunks),
        create = function()
            local s = socket.tcp()
            s:settimeout(timeout)
            return s
        end,
    }
    if body then
        req.source = ltn12.source.string(body)
        req.headers = {
            ["content-type"] = "text/plain",
            ["content-length"] = tostring(#body),
        }
    end
    local ok, code = http.request(req)
    http.TIMEOUT = saved
    if not ok then return nil, tostring(code) end
    if code ~= 200 then return nil, "HTTP " .. tostring(code) end
    return table.concat(chunks)
end

local function requestJson(method, path, body, timeout)
    local text, err = request(method, path, body, timeout)
    if not text then return nil, err end
    local rapidjson = require("rapidjson")
    local data, perr = rapidjson.decode(text)
    if not data then return nil, "json decode: " .. tostring(perr) end
    if data.ok == false then return nil, data.error or "helper error" end
    return data
end

function M.installed()
    local lfs = require("libs/libkoreader-lfs")
    return lfs.attributes(M.BIN, "mode") == "file"
end

function M.health()
    return requestJson("GET", "/health") ~= nil
end

-- Daemon state and build, for the status panel. nil when nothing is listening.
function M.status()
    return requestJson("GET", "/status")
end

-- Spawn the helper the way MapperManager.sh does if it isn't up yet.
function M.ensureHelper()
    if M.health() then return true end
    if not M.installed() then return false, "Button Mapper is not installed" end
    os.execute(string.format(
        "sh -c '%s --waf-helper %s >>%s 2>&1 & echo $! > %s' 2>/dev/null",
        M.BIN, M.CONFIG, M.LOG, M.PIDFILE))
    local ffiutil = require("ffi/util")
    for _ = 1, 10 do
        ffiutil.usleep(200000)
        if M.health() then return true end
    end
    return false, "helper did not come up"
end

function M.getConfig()
    return request("GET", "/config")
end

function M.setConfig(text)
    return requestJson("POST", "/config", text)
end

function M.reload()
    return requestJson("POST", "/reload", "")
end

function M.actions()
    local data, err = requestJson("GET", "/actions")
    return data and data.actions, err
end

-- Evdev node path for a registered device, nil when it isn't connected.
function M.findNode(uniq)
    local data = requestJson("GET", "/devices")
    if not data then return nil end
    local want = M.bareAddr(uniq)
    for _, dev in ipairs(data.devices or {}) do
        if dev.uniq and dev.uniq ~= "" and M.bareAddr(dev.uniq) == want then
            return dev.path
        end
    end
end

-- Blocks up to timeout_ms while the helper reads the device, so the caller
-- must have painted its "press a button" message first.
function M.capture(node, timeout_ms)
    timeout_ms = timeout_ms or 8000
    local path = string.format("/capture?device=%s&timeout=%d",
        node:gsub("[^%w/%-_.]", function(c)
            return string.format("%%%02X", c:byte())
        end), timeout_ms)
    return requestJson("GET", path, nil, timeout_ms / 1000 + 3)
end

------------------------------------------------------------------------------
-- Config text handling (pure)
------------------------------------------------------------------------------

function M.bareAddr(addr)
    return (addr or ""):match("^[^/]*"):upper()
end

local function splitLines(text)
    local lines = {}
    for line in (text .. "\n"):gmatch("([^\n]*)\n") do
        lines[#lines + 1] = line
    end
    -- The split adds a phantom empty line when text already ends in \n.
    if lines[#lines] == "" then lines[#lines] = nil end
    return lines
end

local function sectionOf(line)
    return line:match("^%s*%[(.-)%]%s*$")
end

-- Ordered { id, name, uniq } for every [device.X] block.
function M.deviceBlocks(text)
    local out, byId, current = {}, {}, nil
    for _, line in ipairs(splitLines(text)) do
        local header = sectionOf(line)
        if header then
            local id = header:match("^device%.([^%.]+)$")
            if id then
                if not byId[id] then
                    byId[id] = { id = id }
                    out[#out + 1] = byId[id]
                end
                current = byId[id]
            else
                current = nil
            end
        elseif current then
            local k, v = line:match("^%s*([%w_]+)%s*=%s*(.-)%s*$")
            if k == "name" then current.name = v end
            if k == "uniq" then current.uniq = v end
        end
    end
    return out
end

-- Ordered { key = ..., value = ... } pairs inside [section].
function M.sectionKeys(text, section)
    local out, active = {}, false
    for _, line in ipairs(splitLines(text)) do
        local header = sectionOf(line)
        if header then
            active = (header == section)
        elseif active then
            local k, v = line:match("^%s*([^=%s]+)%s*=%s*(.-)%s*$")
            if k and not k:match("^[#;]") then
                out[#out + 1] = { key = k, value = v }
            end
        end
    end
    return out
end

-- One value from [section], or nil when the key isn't there.
function M.sectionValue(text, section, key)
    for dummy, entry in ipairs(M.sectionKeys(text, section)) do -- luacheck: ignore dummy
        if entry.key == key then return entry.value end
    end
end

-- Set key = value inside [section], creating either as needed.
function M.setKey(text, section, key, value)
    local lines = splitLines(text)
    local current, last_in_section
    for i, line in ipairs(lines) do
        local header = sectionOf(line)
        if header then current = header end
        if current == section then
            if not header then
                local k = line:match("^%s*([^=%s]+)%s*=")
                if k == key then
                    lines[i] = key .. " = " .. value
                    return table.concat(lines, "\n") .. "\n"
                end
            end
            -- Track the last line that carries something, so a new key lands
            -- against the block rather than after the blank line under it.
            if line:match("%S") then last_in_section = i end
        end
    end
    if last_in_section then
        table.insert(lines, last_in_section + 1, key .. " = " .. value)
    else
        if #lines > 0 and lines[#lines] ~= "" then lines[#lines + 1] = "" end
        lines[#lines + 1] = "[" .. section .. "]"
        lines[#lines + 1] = key .. " = " .. value
    end
    return table.concat(lines, "\n") .. "\n"
end

function M.removeKey(text, section, key)
    local lines = splitLines(text)
    local current
    for i, line in ipairs(lines) do
        local header = sectionOf(line)
        if header then current = header end
        if current == section and not header then
            local k = line:match("^%s*([^=%s]+)%s*=")
            if k == key then
                table.remove(lines, i)
                return table.concat(lines, "\n") .. "\n"
            end
        end
    end
    return text
end

------------------------------------------------------------------------------
-- Capture result -> config location
------------------------------------------------------------------------------

local DPAD_DIRECTION = {
    [16] = { [-1] = "left", [1] = "right" },
    [17] = { [-1] = "up",   [1] = "down" },
}
local TRIGGER_NAME = { [9] = "rt", [10] = "lt" }

-- Section and key a captured press maps to, plus a human label.
function M.captureTarget(dev_id, cap)
    if cap.kind == "key" then
        return "device." .. dev_id .. ".buttons", tostring(cap.code),
            "button " .. tostring(cap.code)
    end
    if cap.kind == "dpad" then
        local dir = DPAD_DIRECTION[cap.code]
        dir = dir and dir[cap.value > 0 and 1 or -1]
        if dir then
            return "device." .. dev_id .. ".dpad", dir, "D-pad " .. dir
        end
    end
    if cap.kind == "trigger" then
        local name = TRIGGER_NAME[cap.code]
        if name then
            return "device." .. dev_id .. ".triggers", name, name:upper() .. " trigger"
        end
    end
    return nil
end

function M.actionScript(action)
    return string.format("%s/%s.sh %s", M.SCRIPTS, action.kind, action.id)
end

-- Any KOReader event the HTTP Inspector accepts, which is the whole
-- no-argument half of KOReader's Dispatcher list.
function M.koreaderEventScript(event)
    return string.format("%s/koreader.sh event %s", M.SCRIPTS, event)
end

-- The daemon's own media control. It pauses by no longer draining the audio
-- FIFO, so the writer blocks and whatever is playing freezes in place. That
-- works for any application, unlike a KOReader event, which only reaches the
-- plugin that happens to own the playback.
function M.mediaScript(command)
    return string.format("%s %s", M.MEDIA, command)
end

-- Human label for a configured value, for the mapping list. `titles` maps both
-- KOReader event names and whole script lines to the wording the picker used,
-- so the list reads back the way it was set rather than as a shell command.
function M.describeScript(script, titles)
    script = script:gsub("%s+$", "")
    local event = script:match("koreader%.sh event ([%w_]+)$")
    if event then
        return titles and titles[event] or event
    end
    local known = titles and titles[script]
    if known then return known end
    -- Something hand-written or from another tool. The bare command is the
    -- most useful thing left to show.
    return script:match("([^/]+)$") or script
end

return M
