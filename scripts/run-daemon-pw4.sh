#!/bin/sh

BASE="/mnt/us/kindle_hid_passthrough"
MODULE_DIR="$BASE/dist/kindle_hid_passthrough/modules"

cd "$BASE" || exit 1

ensure_uhid() {
    [ -e /dev/uhid ] && return 0

    UNAME_R=$(uname -r 2>/dev/null)
    VERSION_LINE=$(sed -n '1s/^System Software Version: //p' /etc/version.txt 2>/dev/null)
    BUILD=$(printf '%s\n' "$VERSION_LINE" | sed -n 's/.*-\([0-9][0-9]*\)$/\1/p')
    CODENAME=$(printf '%s\n' "$VERSION_LINE" | sed -n 's/.*_\([a-z][a-z0-9]*\)-[0-9][0-9]*$/\1/p')

    if [ -n "$UNAME_R" ] && [ -n "$BUILD" ] && [ -n "$CODENAME" ]; then
        MODULE="$MODULE_DIR/uhid-$UNAME_R-$BUILD-$CODENAME.ko"
        if [ -f "$MODULE" ]; then
            insmod "$MODULE" 2>/dev/null || true
        fi
    fi
}

ensure_uhid

export GLIBC_TUNABLES="glibc.cpu.hwcap_mask=0x40"
export LD_PRELOAD="$BASE/libsyscall_wrapper.so"
export KINDLE_HID_BASE="$BASE"

exec "$BASE/dist/ld-linux-armhf.so.3" --library-path "$BASE/dist" "$BASE/dist/main.bin" --daemon
