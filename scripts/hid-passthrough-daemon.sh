#!/bin/sh

# Script to start and stop the kindle-hid-passthrough daemon
PROCESS_NAME="kindle-hid-passthrough"
LD_PROCESS="ld-linux-armhf."
RUNNER="/mnt/us/kindle_hid_passthrough/scripts/run-daemon-pw4.sh"
API_URL="http://127.0.0.1:8321"
START_TIMEOUT=30

alert() {
    TITLE="$1"
    TEXT="$2"

    TITLE_ESC=$(printf '%s' "$TITLE" | sed 's/"/\\"/g')
    TEXT_ESC=$(printf '%s' "$TEXT" | sed 's/"/\\"/g')

    JSON='{ "clientParams":{ "alertId":"appAlert1", "show":true, "customStrings":[ { "matchStr":"alertTitle", "replaceStr":"'"$TITLE_ESC"'" }, { "matchStr":"alertText", "replaceStr":"'"$TEXT_ESC"'" } ] } }'

    lipc-set-prop com.lab126.pillow pillowAlert "$JSON" 2>/dev/null || true
}

http_get() {
    curl -fsS "$API_URL$1" 2>/dev/null || wget -qO- "$API_URL$1" 2>/dev/null || true
}

has_uhid() {
    [ -e /dev/uhid ]
}

get_state() {
    STATUS=$(http_get /status)
    if printf '%s' "$STATUS" | grep -q '"daemon_running"[[:space:]]*:[[:space:]]*true'; then
        printf '%s\n' on
    elif [ -n "$STATUS" ]; then
        printf '%s\n' api_only
    else
        printf '%s\n' off
    fi
}

wait_for_state() {
    TARGET="$1"
    TICKS="$2"
    i=0
    while [ "$i" -lt "$TICKS" ]; do
        [ "$(get_state)" = "$TARGET" ] && return 0
        sleep 1
        i=$((i + 1))
    done
    return 1
}

kill_daemon_pids() {
    PIDS=$(pgrep -f "$LD_PROCESS" 2>/dev/null)
    for PID in $PIDS; do
        [ "$PID" = "$$" ] && continue
        [ "$PID" = "$PPID" ] && continue
        kill -TERM "$PID" 2>/dev/null || true
    done
    sleep 2
    PIDS=$(pgrep -f "$LD_PROCESS" 2>/dev/null)
    for PID in $PIDS; do
        [ "$PID" = "$$" ] && continue
        [ "$PID" = "$PPID" ] && continue
        kill -KILL "$PID" 2>/dev/null || true
    done
}

start() {
  STATE=$(get_state)
  if [ "$STATE" = "on" ]; then
    if has_uhid; then
        alert "HID Passthrough Already Running" "The HID passthrough daemon is already running."
        return 0
    fi
    alert "Repairing HID Passthrough" "Daemon is up, but /dev/uhid is missing. Restarting the HID layer..."
    kill_daemon_pids
    sleep 2
    STATE=off
  fi
  if [ "$STATE" = "api_only" ]; then
    alert "Starting HID Passthrough" "The HID passthrough daemon is starting. Please wait for the keyboard to connect..."
    http_get /start >/dev/null
    if wait_for_state on "$START_TIMEOUT" && has_uhid; then
        return 0
    fi
    # API server is alive but won't re-enable the HID layer. Restart the
    # wrapper process cleanly, then bring both layers back with the runner.
    kill_daemon_pids
    sleep 2
  fi
  alert "Starting HID Passthrough" "The HID passthrough daemon is starting. Please wait for the keyboard to connect..."
  "$RUNNER" &
}

stop() {
  PIDS=$(pgrep -f "$LD_PROCESS" 2>/dev/null)
  if [ -n "$PIDS" ]; then
    alert "Stopping HID Passthrough" "The HID passthrough daemon is stopping..."
    kill_daemon_pids
  else
    alert "HID Passthrough Not Running" "The HID passthrough daemon is not currently running."
  fi
}

# Main script logic

case "$1" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  *)
    echo "Usage: $0 {start|stop}"
    exit 1
    ;;
esac

exit 0
