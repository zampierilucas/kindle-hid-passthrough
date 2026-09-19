#!/bin/sh
# ==============================================================================
# Media control for the daemon's audio path.
#
# Pauses whatever is playing, whoever is playing it: the daemon stops draining
# /tmp/kindle_audio.fifo, the writer blocks and freezes in place, and resuming
# picks up at the same sample. No cooperation from the playing application.
#
# Map a button to this from the button mapper, for example:
#   [device.headset.buttons]
#   play_pause = /mnt/us/kindle_hid_passthrough/assets/audio-hack/media.sh toggle
# ==============================================================================

API="http://127.0.0.1:8321"

usage() {
    echo "usage: $(basename "$0") {toggle|play|pause|status}" >&2
    exit 2
}

[ $# -eq 1 ] || usage

case "$1" in
    toggle|play|pause) path="/media/$1" ;;
    status)            path="/status" ;;
    *)                 usage ;;
esac

if command -v wget >/dev/null 2>&1; then
    wget -qO- "$API$path"
elif command -v curl >/dev/null 2>&1; then
    curl -s "$API$path"
else
    echo "media.sh: neither wget nor curl available" >&2
    exit 1
fi
