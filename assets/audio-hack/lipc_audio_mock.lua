#!/mnt/us/koreader/luajit
-- ============================================================================
-- LIPC Audio Manager Spoofing Daemon (Milestone M2)
-- Target: /mnt/us/kindle_hid_passthrough/teamwork_audio_hack/lipc_audio_mock.lua
-- Service: com.lab126.audiomgrd
--
-- Exposes spoofed LIPC properties to satisfy KOReader audio checks without
-- modifying any KOReader source code.
-- ============================================================================

local ffi = require("ffi")

ffi.cdef[[
typedef void* LipcHandle;
typedef int LipcErr;

typedef LipcErr (*LipcGetIntCb)(LipcHandle h, const char* name, int* val, void* user_data);
typedef LipcErr (*LipcSetIntCb)(LipcHandle h, const char* name, int val, void* user_data);
typedef LipcErr (*LipcGetStrCb)(LipcHandle h, const char* name, char* val, size_t* len, void* user_data);
typedef LipcErr (*LipcSetStrCb)(LipcHandle h, const char* name, const char* val, void* user_data);

LipcHandle LipcOpen(const char* service_name);
LipcErr LipcClose(LipcHandle h);
LipcErr LipcRegisterIntProperty(LipcHandle h, const char* name, LipcGetIntCb get_cb, LipcSetIntCb set_cb, void* user_data);
LipcErr LipcRegisterStringProperty(LipcHandle h, const char* name, LipcGetStrCb get_cb, LipcSetStrCb set_cb, void* user_data);
LipcErr LipcStartListener(LipcHandle h);
LipcErr LipcStopListener(LipcHandle h);

typedef void (*sighandler_t)(int);
sighandler_t signal(int signum, sighandler_t handler);
unsigned int sleep(unsigned int seconds);
int usleep(unsigned int usec);
]]

local liblipc = ffi.load("/usr/lib/liblipc.so.1")

-- Internal property state table
local int_props = {
    audioOutputConnected = 1,
    audioCurrentOutput   = 1,
    speakerVolume        = 100,
    headphoneVolume      = 100,
    isStarted            = 1,
}

local str_props = {
    setFocus = "tts",
    getFocus = "tts",
    logLevel = "info",
    logMask  = "0x0fff0000",
}

-- Hold references to C callbacks to prevent LuaJIT garbage collection
local callbacks = {}

callbacks.get_int = ffi.cast("LipcGetIntCb", function(h, name, val_ptr, user_data)
    if name == nil or val_ptr == nil then return 1 end
    local prop = ffi.string(name)
    val_ptr[0] = int_props[prop] or 0
    return 0
end)

callbacks.set_int = ffi.cast("LipcSetIntCb", function(h, name, val, user_data)
    if name == nil then return 1 end
    local prop = ffi.string(name)
    int_props[prop] = val
    return 0
end)

callbacks.get_str = ffi.cast("LipcGetStrCb", function(h, name, val_buf, len_ptr, user_data)
    if name == nil or val_buf == nil or len_ptr == nil then return 1 end
    local prop = ffi.string(name)
    local str_val = str_props[prop] or ""
    local max_len = tonumber(len_ptr[0])
    local needed = #str_val + 1
    if max_len < needed then
        len_ptr[0] = needed
        return 10 -- LIPC_ERR_BUF_TOO_SMALL
    end
    ffi.copy(val_buf, str_val)
    return 0
end)

callbacks.set_str = ffi.cast("LipcSetStrCb", function(h, name, val, user_data)
    if name == nil then return 1 end
    local prop = ffi.string(name)
    if val ~= nil then
        local s = ffi.string(val)
        str_props[prop] = s
        if prop == "setFocus" then
            str_props["getFocus"] = s
        end
    end
    return 0
end)

-- Signal handling for graceful shutdown
local running = true
callbacks.sig_handler = ffi.cast("sighandler_t", function(signum)
    running = false
end)

-- Register signals: SIGTERM(15), SIGINT(2), SIGHUP(1), SIGQUIT(3)
ffi.C.signal(15, callbacks.sig_handler)
ffi.C.signal(2, callbacks.sig_handler)
ffi.C.signal(1, callbacks.sig_handler)
ffi.C.signal(3, callbacks.sig_handler)

local SERVICE_NAME = "com.lab126.audiomgrd"

local h = liblipc.LipcOpen(SERVICE_NAME)
if h == nil then
    io.stderr:write(string.format("[lipc_audio_mock] ERROR: LipcOpen('%s') failed (is stock audiomgrd still running?)\n", SERVICE_NAME))
    io.stderr:flush()
    os.exit(1)
end

-- Register integer properties
-- Read-only: audioOutputConnected, audioCurrentOutput, isStarted
-- Read-write: speakerVolume, headphoneVolume
liblipc.LipcRegisterIntProperty(h, "audioOutputConnected", callbacks.get_int, nil, nil)
liblipc.LipcRegisterIntProperty(h, "audioCurrentOutput",   callbacks.get_int, nil, nil)
liblipc.LipcRegisterIntProperty(h, "speakerVolume",        callbacks.get_int, callbacks.set_int, nil)
liblipc.LipcRegisterIntProperty(h, "headphoneVolume",      callbacks.get_int, callbacks.set_int, nil)
liblipc.LipcRegisterIntProperty(h, "isStarted",            callbacks.get_int, nil, nil)

-- Register string properties
-- Write-only: setFocus
-- Read-only: getFocus
-- Read-write: logLevel, logMask
liblipc.LipcRegisterStringProperty(h, "setFocus", nil, callbacks.set_str, nil)
liblipc.LipcRegisterStringProperty(h, "getFocus", callbacks.get_str, nil, nil)
liblipc.LipcRegisterStringProperty(h, "logLevel", callbacks.get_str, callbacks.set_str, nil)
liblipc.LipcRegisterStringProperty(h, "logMask",  callbacks.get_str, callbacks.set_str, nil)

local start_err = liblipc.LipcStartListener(h)
if start_err ~= 0 then
    io.stderr:write(string.format("[lipc_audio_mock] ERROR: LipcStartListener failed with code %d\n", start_err))
    io.stderr:flush()
    liblipc.LipcClose(h)
    os.exit(1)
end

print(string.format("[lipc_audio_mock] Service '%s' successfully registered and listening.", SERVICE_NAME))
io.stdout:flush()

-- Main loop: sleep until signal received
while running do
    ffi.C.sleep(1)
end

print("[lipc_audio_mock] Termination signal caught, shutting down cleanly...")
io.stdout:flush()

liblipc.LipcStopListener(h)
liblipc.LipcClose(h)

print("[lipc_audio_mock] Clean shutdown complete.")
io.stdout:flush()
os.exit(0)
