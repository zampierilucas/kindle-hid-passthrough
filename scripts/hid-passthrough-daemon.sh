#!/bin/sh

# Script to start and stop the kindle-hid-passthrough daemon
PROCESS_NAME="kindle-hid-passthrough"
LD_PROCESS="ld-linux-armhf."

alert() {
    TITLE="$1"
    TEXT="$2"

    TITLE_ESC=$(printf '%s' "$TITLE" | sed 's/"/\\"/g')
    TEXT_ESC=$(printf '%s' "$TEXT" | sed 's/"/\\"/g')

    JSON='{ "clientParams":{ "alertId":"appAlert1", "show":true, "customStrings":[ { "matchStr":"alertTitle", "replaceStr":"'"$TITLE_ESC"'" }, { "matchStr":"alertText", "replaceStr":"'"$TEXT_ESC"'" } ] } }'

    lipc-set-prop com.lab126.pillow pillowAlert "$JSON" 2>/dev/null || true
}

start() {
  lipc-set-prop -s com.lab126.btfd BTenable 0:1
  alert "Starting HID Passthrough" "The HID passthrough daemon is starting. Please wait for the keyboard to connect..."
  /mnt/us/kindle_hid_passthrough/$PROCESS_NAME --daemon &
}

stop() {
  PID=$(pgrep -f "$LD_PROCESS")
  if [ -n "$PID" ]; then
    alert "Stopping HID Passthrough" "The HID passthrough daemon is stopping..."
    # Gracefully kill the process (SIGTERM)
    kill -TERM "$PID"
    wait "$PID" 2>/dev/null  # Suppress errors if process already gone
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
