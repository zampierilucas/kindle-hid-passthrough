#!/bin/sh
# ==============================================================================
# Amazon Kindle Audio Bypass - Service Startup Script
# Part of the kindle-hid-passthrough audio bypass
#
# Installs the gst-launch wrapper, ensures the audio FIFO exists, stops stock
# audiomgrd, launches the mock LIPC daemon under the process name 'audiomgrd',
# and confirms service readiness.
# ==============================================================================

set -e

WORK_DIR="$(cd "$(dirname "$0")" && pwd)"
MOCK_SCRIPT="$WORK_DIR/lipc_audio_mock.lua"
SYMLINK_BIN="/tmp/audiomgrd"
FIFO="/tmp/kindle_audio.fifo"
LOG_FILE="/tmp/audiomgrd_mock.log"

log_info() {
    echo "[start_audio_hack] INFO: $1"
}

log_warn() {
    echo "[start_audio_hack] WARN: $1" >&2
}

log_error() {
    echo "[start_audio_hack] ERROR: $1" >&2
}

# 0. The mock runs under KOReader's LuaJIT. Check the interpreter before
#    touching anything: stopping the stock audiomgrd and then failing to
#    start a replacement leaves the device with no audio at all.
LUAJIT="/mnt/us/koreader/luajit"
if [ ! -x "$LUAJIT" ]; then
    log_error "LuaJIT not found at $LUAJIT (KOReader not installed?)."
    log_error "Leaving the stock audio daemon running."
    exit 1
fi

# 1. Put the gst-launch wrapper in place. It is what rewrites the pipeline's
#    sink into the FIFO; without it nothing ever writes there, the reader
#    drains an empty pipe and the sink receives silence -- which from the
#    outside is indistinguishable from a working bypass. Do this before
#    stopping the stock daemon, so a failure here leaves audio untouched.
WRAPPER="$WORK_DIR/gst-launch-wrapper.sh"
GST="/usr/bin/gst-launch-0.10"
GST_REAL="$GST.real"

if [ ! -f "$WRAPPER" ]; then
    log_error "Wrapper missing at $WRAPPER."
    log_error "Leaving the stock audio daemon running."
    exit 1
fi

/usr/sbin/mntroot rw >/dev/null 2>&1 || true
# Only wrap a stock binary we could actually set aside: a wrapper with no
# .real to delegate to makes every gst call exit 127, and overwriting the
# stock binary without saving it is unrecoverable.
if [ ! -f "$GST_REAL" ]; then
    if [ ! -f "$GST" ]; then
        log_error "No stock gst-launch-0.10 on this firmware."
        /usr/sbin/mntroot ro >/dev/null 2>&1 || true
        exit 1
    fi
    if ! mv "$GST" "$GST_REAL"; then
        log_error "Could not set the stock gst-launch-0.10 aside."
        /usr/sbin/mntroot ro >/dev/null 2>&1 || true
        exit 1
    fi
fi
# Copied every time, not only when .real is created: this is also the repair
# path after an update or an uninstall put the stock binary back.
if cp "$WRAPPER" "$GST" && chmod +x "$GST"; then
    /usr/sbin/mntroot ro >/dev/null 2>&1 || true
    log_info "gst-launch wrapper in place (stock kept at $GST_REAL)"
else
    /usr/sbin/mntroot ro >/dev/null 2>&1 || true
    log_error "Could not install the gst-launch wrapper."
    exit 1
fi

# 2. Ensure FIFO exists with mode 0666
if [ ! -p "$FIFO" ]; then
    rm -f "$FIFO" 2>/dev/null || true
    mkfifo -m 666 "$FIFO" 2>/dev/null || mkfifo "$FIFO" 2>/dev/null
    chmod 666 "$FIFO" 2>/dev/null || true
    log_info "Audio FIFO verified at $FIFO"
fi

# 3. Ensure symlink to luajit exists with name 'audiomgrd'
if [ ! -L "$SYMLINK_BIN" ] || [ "$(readlink "$SYMLINK_BIN" 2>/dev/null)" != "$LUAJIT" ]; then
    log_info "Creating audiomgrd symlink -> $LUAJIT"
    ln -sf "$LUAJIT" "$SYMLINK_BIN"
fi

# 4. Check if mock daemon is already running and responsive
if pidof audiomgrd >/dev/null 2>&1; then
    for pid in $(pidof audiomgrd); do
        cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
        if echo "$cmdline" | grep -q "lipc_audio_mock.lua"; then
            val=$(lipc-get-prop com.lab126.audiomgrd audioOutputConnected 2>/dev/null || true)
            if [ "$val" = "1" ]; then
                log_info "Mock audiomgrd is already running (PID $pid) and responsive."
                exit 0
            fi
            # Stale mock daemon, terminate it
            log_warn "Mock audiomgrd (PID $pid) is unresponsive. Terminating..."
            kill -9 "$pid" 2>/dev/null || true
        fi
    done
fi

# 5. Stop stock audiomgrd service
if initctl status audiomgrd 2>/dev/null | grep -q "start/running"; then
    log_info "Stopping stock audiomgrd via Upstart..."
    initctl stop audiomgrd 2>/dev/null || true
    sleep 1
fi

# Kill any remaining stock audiomgrd processes
if pidof audiomgrd >/dev/null 2>&1; then
    for pid in $(pidof audiomgrd); do
        cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
        if echo "$cmdline" | grep -qv "lipc_audio_mock.lua"; then
            log_info "Terminating dangling stock audiomgrd (PID $pid)..."
            kill -9 "$pid" 2>/dev/null || true
        fi
    done
    sleep 1
fi

# 6. Launch mock daemon in background under symlinked name with setsid/nohup
log_info "Launching mock audiomgrd daemon..."
if [ -x /usr/bin/setsid ]; then
    /usr/bin/setsid "$SYMLINK_BIN" "$MOCK_SCRIPT" >"$LOG_FILE" 2>&1 &
elif [ -x /usr/bin/nohup ]; then
    /usr/bin/nohup "$SYMLINK_BIN" "$MOCK_SCRIPT" >"$LOG_FILE" 2>&1 &
else
    "$SYMLINK_BIN" "$MOCK_SCRIPT" >"$LOG_FILE" 2>&1 &
fi
MOCK_PID=$!

# 7. Wait and verify that the daemon registered the LIPC service
READY=0
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    val=$(lipc-get-prop com.lab126.audiomgrd audioOutputConnected 2>/dev/null || true)
    if [ "$val" = "1" ]; then
        READY=1
        break
    fi
    usleep 200000 2>/dev/null || sleep 1
done

if [ "$READY" -eq 1 ]; then
    log_info "Audio hack daemon started successfully (audioOutputConnected=1)."
    exit 0
else
    log_error "Mock daemon failed to register com.lab126.audiomgrd within timeout."
    cat "$LOG_FILE" >&2 2>/dev/null || true
    log_warn "Restoring the stock audio daemon."
    initctl start audiomgrd 2>/dev/null || true
    exit 1
fi
