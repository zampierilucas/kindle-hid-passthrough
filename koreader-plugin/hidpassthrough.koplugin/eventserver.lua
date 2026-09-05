local Event = require("ui/event")
local UIManager = require("ui/uimanager")
local logger = require("logger")
local util = require("util")

local M = {
    HOST = "127.0.0.1",
    PORT = 8323,
}

local server

local function parseArgs(uri)
    local args, n = {}, 0
    local i, len = 1, #uri
    while i <= len do
        local c = uri:sub(i, i)
        if c == "/" then
            i = i + 1
        elseif c == '"' or c == "'" then
            local close = uri:find(c, i + 1, true) or len + 1
            n = n + 1
            args[n] = uri:sub(i + 1, close - 1)
            i = close + 1
        else
            local stop = uri:find("/", i, true) or len + 1
            local text = uri:sub(i, stop - 1)
            n = n + 1
            if text == "true" then
                args[n] = true
            elseif text == "false" then
                args[n] = false
            elseif text == "nil" then
                args[n] = nil
            else
                args[n] = tonumber(text) or text
            end
            i = stop + 1
        end
    end
    return args, n
end

function M.parseRequest(data)
    local method, path = data:match("^(%u+) (%S+)")
    if method ~= "GET" or not path then return nil end
    local uri = util.urlDecode(path):match("^/koreader/event/(.+)$")
    if not uri then return nil end
    local args, n = parseArgs(uri)
    if n == 0 or type(args[1]) ~= "string" then return nil end
    return args, n
end

local function onRequest(data, client)
    local args, n = M.parseRequest(data)
    local code, body
    if args then
        UIManager:nextTick(function()
            UIManager:sendEvent(Event:new(table.unpack(args, 1, n)))
        end)
        code, body = "200 OK", "OK"
    else
        code, body = "400 Bad Request", "Bad request"
    end
    if server then
        server:send(string.format(
            "HTTP/1.0 %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
            code, #body, body), client)
    end
    return Event:new("InputEvent")
end

function M.start()
    if server then return true end
    local SimpleTCPServer = require("ui/message/simpletcpserver")
    server = SimpleTCPServer:new{
        host = M.HOST,
        port = M.PORT,
        receiveCallback = onRequest,
    }
    local ok, err = server:start()
    if not ok then
        logger.warn("HIDPassthrough: event server:", err)
        server = nil
        return false
    end
    UIManager:insertZMQ(server)
    logger.dbg("HIDPassthrough: event server on port", M.PORT)
    return true
end

function M.stop()
    if not server then return end
    UIManager:removeZMQ(server)
    server:stop()
    server = nil
end

return M
