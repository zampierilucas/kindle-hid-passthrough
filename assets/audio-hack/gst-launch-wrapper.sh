#!/bin/sh
# ==============================================================================
# Amazon Kindle GStreamer 0.10 Interception & Redirection Wrapper
# Part of the kindle-hid-passthrough audio bypass
#
# Intercepts GStreamer 0.10 audio pipelines specifying 'mixersink' (which block
# when stock btmanagerd/audiomgrd are inactive) and transparently redirects
# PCM audio to /tmp/kindle_audio.fifo using 'filesink'.
#
# Emits audio format (rate and channels) dynamically to /tmp/kindle_audio.fmt.
# Injects --gst-debug="mixersink stream-type=Music:0" for process visibility.
#
# KOReader source code remains 100% untouched.
# Compatible with BusyBox ash and POSIX /bin/sh.
# ==============================================================================

# Destination FIFO for userspace audio streaming
FIFO="${KINDLE_AUDIO_FIFO:-/tmp/kindle_audio.fifo}"
FMT_FILE="/tmp/kindle_audio.fmt"

# Real binary resolution
REAL_BIN="${GST_REAL_BIN:-/usr/bin/gst-launch-0.10.real}"
if [ ! -x "$REAL_BIN" ]; then
    if [ -x "/usr/bin/gst-launch-0.10" ] && [ "$(readlink -f /usr/bin/gst-launch-0.10 2>/dev/null)" != "$(readlink -f "$0" 2>/dev/null)" ]; then
        REAL_BIN="/usr/bin/gst-launch-0.10"
    else
        echo "gst-launch-0.10 wrapper error: cannot locate executable binary $REAL_BIN" >&2
        exit 127
    fi
fi

# Fast Path: Check if 'mixersink' is targeted
has_mixersink=0
for arg in "$@"; do
    if [ "$arg" = "mixersink" ]; then
        has_mixersink=1
        break
    fi
done

# If mixersink is not in argument list, pass through directly
if [ "$has_mixersink" -eq 0 ]; then
    exec "$REAL_BIN" "$@"
fi

# Ensure FIFO exists with 0666 permissions (do not recreate if already a named pipe)
if [ ! -p "$FIFO" ]; then
    if [ -e "$FIFO" ] || [ -L "$FIFO" ]; then
        rm -f "$FIFO" 2>/dev/null
    fi
    mkfifo -m 666 "$FIFO" 2>/dev/null || mkfifo "$FIFO" 2>/dev/null
    chmod 666 "$FIFO" 2>/dev/null || true
fi

# Extract audio format parameters (rate and channels) from caps if present
fmt_rate=""
fmt_channels=""

for a in "$@"; do
    case "$a" in
        rate=*|*,rate=*)
            r="${a#*rate=}"
            case "$r" in
                \(int\)*) r="${r#\(int\)}" ;;
            esac
            while [ "${r# }" != "$r" ]; do r="${r# }"; done
            r="${r%%,*}"
            r="${r%% *}"
            r="${r%%\'*}"
            r="${r%%\"*}"
            case "$r" in
                ''|*[!0-9]*) ;;
                *) fmt_rate="$r" ;;
            esac
            ;;
    esac
    case "$a" in
        channels=*|*,channels=*)
            c="${a#*channels=}"
            case "$c" in
                \(int\)*) c="${c#\(int\)}" ;;
            esac
            while [ "${c# }" != "$c" ]; do c="${c# }"; done
            c="${c%%,*}"
            c="${c%% *}"
            c="${c%%\'*}"
            c="${c%%\"*}"
            case "$c" in
                ''|*[!0-9]*) ;;
                *) fmt_channels="$c" ;;
            esac
            ;;
    esac
done

# Both or neither: publishing a guessed rate next to a real channel count made
# the daemon resample against a rate the pipeline never had. With nothing
# written the daemon keeps the format it is already using, which is no worse
# than the guess and is at least honest about not knowing.
if [ -n "$fmt_rate" ] && [ -n "$fmt_channels" ]; then
    echo "rate=$fmt_rate channels=$fmt_channels" > "${FMT_FILE}.tmp" 2>/dev/null &&
        mv -f "${FMT_FILE}.tmp" "$FMT_FILE" 2>/dev/null || true
fi

# Transform argument vector: replace mixersink with filesink and drop incompatible sink properties
ORIG_COUNT=$#
i=0
in_mixersink=0

while [ $i -lt "$ORIG_COUNT" ]; do
    arg="$1"
    shift
    i=$((i + 1))

    if [ "$arg" = "mixersink" ]; then
        in_mixersink=1
        set -- "$@" "filesink" "location=$FIFO" "sync=true"
    elif [ "$in_mixersink" -eq 1 ]; then
        case "$arg" in
            "!"|--*|-*)
                in_mixersink=0
                set -- "$@" "$arg"
                ;;
            *=*)
                # Drop property tokens targeted at mixersink (stream-type=*, sync=*, buffer-time=*, etc.)
                ;;
            *)
                in_mixersink=0
                set -- "$@" "$arg"
                ;;
        esac
    else
        set -- "$@" "$arg"
    fi
done

# Prepend debug flag to ensure 'mixersink stream-type=Music' remains in /proc/$PID/cmdline
# This guarantees that KOReader's `pkill -9 -f 'mixersink stream-type=Music'` cleanly terminates playback.
set -- "--gst-debug=mixersink stream-type=Music:0" "$@"

# Replace current process with real GStreamer binary
exec "$REAL_BIN" "$@"
