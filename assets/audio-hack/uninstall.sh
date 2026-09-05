#!/bin/sh
# ==============================================================================
# Amazon Kindle Audio Bypass - Uninstallation Script
# Part of the kindle-hid-passthrough audio bypass
#
# Restores genuine /usr/bin/gst-launch-0.10 binary, stops mock LIPC daemon,
# cleans up Upstart pre-start persistence hooks, and restores rootfs to read-only.
# ==============================================================================

set -e

WORK_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET="/usr/bin/gst-launch-0.10"
TARGET_REAL="/usr/bin/gst-launch-0.10.real"
BACKUP_DIR="$WORK_DIR/backup"
BACKUP_COPY="$BACKUP_DIR/gst-launch-0.10.orig"
UPSTART_CONF="/etc/upstart/hid-passthrough.conf"
UPSTART_ASSET="/mnt/us/kindle_hid_passthrough/assets/hid-passthrough.upstart"

# Logging helpers
log_info() {
    echo "[uninstall.sh] INFO: $1"
}

log_warn() {
    echo "[uninstall.sh] WARN: $1" >&2
}

log_error() {
    echo "[uninstall.sh] ERROR: $1" >&2
}

# Root filesystem remount helpers
remount_rw() {
    if [ -x /usr/sbin/mntroot ]; then
        /usr/sbin/mntroot rw >/dev/null 2>&1 || mount -o remount,rw /
    else
        mount -o remount,rw /
    fi
}

remount_ro() {
    sync
    if [ -x /usr/sbin/mntroot ]; then
        /usr/sbin/mntroot ro >/dev/null 2>&1 || mount -o remount,ro /
    else
        mount -o remount,ro /
    fi
}

# Trap to guarantee rootfs is never left rw on exit, error, or interrupt
trap 'remount_ro' EXIT INT TERM HUP

remove_upstart_hook() {
    conf="$1"
    [ -f "$conf" ] || return 0
    if ! grep -q "start_audio_hack.sh" "$conf"; then
        log_info "No Upstart hook found in $conf."
        return 0
    fi
    log_info "Removing start_audio_hack.sh hook from $conf..."
    if [ -x /mnt/us/python3/usr/bin/python3.11 ]; then
        /mnt/us/python3/usr/bin/python3.11 - "$conf" << 'PYEOF'
import sys
conf_path = sys.argv[1]
with open(conf_path, 'r') as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if "start_audio_hack.sh" in line or "Auto-start Kindle audio bypass hack" in line:
        continue
    new_lines.append(line)

with open(conf_path, 'w') as f:
    f.writelines(new_lines)
PYEOF
    else
        sed -i '/start_audio_hack\.sh/d' "$conf"
        sed -i '/Auto-start Kindle audio bypass hack/d' "$conf"
    fi
}

main() {
    log_info "Starting Kindle GStreamer Audio Bypass Uninstallation..."

    # Pre-flight check: Root privileges
    if [ "$(id -u)" -ne 0 ]; then
        log_error "Must run as root."
        exit 1
    fi

    # Step 1: Stop mock daemon if running
    if [ -x "$WORK_DIR/stop_audio_hack.sh" ]; then
        log_info "Stopping audio hack services via stop_audio_hack.sh..."
        "$WORK_DIR/stop_audio_hack.sh" || true
    else
        log_info "Stopping any running mock daemon processes..."
        if pidof audiomgrd >/dev/null 2>&1; then
            for pid in $(pidof audiomgrd); do
                cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
                if echo "$cmdline" | grep -q "lipc_audio_mock.lua"; then
                    log_info "Terminating mock daemon PID $pid..."
                    kill -TERM "$pid" 2>/dev/null || true
                fi
            done
        fi
        # Start stock audiomgrd if not running
        if ! initctl status audiomgrd 2>/dev/null | grep -q "start/running"; then
            log_info "Starting stock audiomgrd..."
            initctl start audiomgrd 2>/dev/null || true
        fi
    fi

    # Step 2: Remount rootfs as RW to restore genuine binary and Upstart config
    log_info "Remounting root filesystem read-write..."
    remount_rw

    # Step 3: Restore genuine binary
    if [ -f "$TARGET_REAL" ]; then
        log_info "Restoring genuine binary $TARGET_REAL -> $TARGET..."
        mv -f "$TARGET_REAL" "$TARGET"
        chmod 0755 "$TARGET"
        chown root:root "$TARGET" 2>/dev/null || true
    elif [ -f "$BACKUP_COPY" ]; then
        log_info "Restoring genuine binary from backup $BACKUP_COPY -> $TARGET..."
        cp -f "$BACKUP_COPY" "$TARGET"
        chmod 0755 "$TARGET"
        chown root:root "$TARGET" 2>/dev/null || true
    else
        if [ -f "$TARGET" ] && head -c 4 "$TARGET" | grep -q 'ELF'; then
            log_info "$TARGET is already the genuine ELF binary. No restore needed."
        else
            log_error "No genuine backup binary found at $TARGET_REAL or $BACKUP_COPY."
            exit 1
        fi
    fi

    sync

    # Step 4: Remove Upstart pre-start hooks
    remove_upstart_hook "$UPSTART_CONF"
    remove_upstart_hook "$UPSTART_ASSET"

    # Reload Upstart configuration
    /sbin/initctl reload-configuration 2>/dev/null || true

    # Step 5: Verification of restored binary
    if [ ! -p "$TARGET" ] && [ ! -x "$TARGET" ]; then
        log_error "Restoration verification failed: $TARGET is not executable."
        exit 1
    fi

    VERSION_OUT=$("$TARGET" --version 2>&1 || true)
    if echo "$VERSION_OUT" | grep -q "gst-launch-0.10"; then
        log_info "Restored GStreamer binary verified: $VERSION_OUT"
    else
        log_warn "Restored binary --version returned unexpected output: $VERSION_OUT"
    fi

    # Step 6: Verify stock audiomgrd status
    if initctl status audiomgrd 2>/dev/null | grep -q "start/running"; then
        log_info "Stock audiomgrd is running."
    else
        log_warn "Stock audiomgrd is not running; attempting to start..."
        initctl start audiomgrd 2>/dev/null || true
    fi

    log_info "Uninstallation completed successfully."
    return 0
}

main "$@"
