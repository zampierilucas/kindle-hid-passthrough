#!/bin/sh
# ==============================================================================
# Amazon Kindle Audio Bypass - Service Teardown Script
# Part of the kindle-hid-passthrough audio bypass
#
# Terminates the mock LIPC daemon and restores the stock gst-launch binary
# and audiomgrd service.
# ==============================================================================

set -e

WORK_DIR="$(cd "$(dirname "$0")" && pwd)"

log_info() {
    echo "[stop_audio_hack] INFO: $1"
}

log_warn() {
    echo "[stop_audio_hack] WARN: $1" >&2
}

log_error() {
    echo "[stop_audio_hack] ERROR: $1" >&2
}

main() {
    log_info "Stopping Kindle Audio Bypass services..."

    # Step 1: Find and terminate mock daemon
    if pidof audiomgrd >/dev/null 2>&1; then
        for pid in $(pidof audiomgrd); do
            cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
            if echo "$cmdline" | grep -q "lipc_audio_mock.lua"; then
                log_info "Sending SIGTERM to mock daemon (PID $pid)..."
                kill -TERM "$pid" 2>/dev/null || true
            fi
        done
        sleep 1

        # Check if mock daemon is still alive and force kill
        for pid in $(pidof audiomgrd 2>/dev/null || true); do
            cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
            if echo "$cmdline" | grep -q "lipc_audio_mock.lua"; then
                log_info "Force killing mock daemon (PID $pid)..."
                kill -9 "$pid" 2>/dev/null || true
            fi
        done
    fi

    # Step 2: Restore the stock gst-launch. The wrapper rewrites any
    # mixersink pipeline into the FIFO whether or not anything is draining
    # it, so leaving it behind once the reader is gone makes the next
    # playback block on the FIFO instead of playing.
    GST="/usr/bin/gst-launch-0.10"
    GST_REAL="$GST.real"
    if [ -f "$GST_REAL" ]; then
        log_info "Restoring the stock gst-launch-0.10..."
        /usr/sbin/mntroot rw >/dev/null 2>&1 || true
        mv -f "$GST_REAL" "$GST" || log_warn "Could not restore $GST."
        /usr/sbin/mntroot ro >/dev/null 2>&1 || true
    fi

    # Step 3: Restart stock audiomgrd
    log_info "Starting stock audiomgrd via Upstart..."
    initctl start audiomgrd 2>/dev/null || true
    sleep 1

    # Step 4: Verify stock audiomgrd status
    RUNNING=0
    for i in 1 2 3 4 5; do
        if initctl status audiomgrd 2>/dev/null | grep -q "start/running"; then
            RUNNING=1
            break
        fi
        sleep 1
    done

    if [ "$RUNNING" -eq 1 ]; then
        log_info "Stock audiomgrd successfully restored."
        return 0
    else
        log_warn "Stock audiomgrd did not report start/running state."
        return 1
    fi
}

main "$@"
