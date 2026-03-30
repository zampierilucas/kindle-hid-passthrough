#!/bin/sh
# Check if an input device is a keyboard via sysfs capabilities.
# Called by udev with %S%p (full sysfs path to eventN node).
# Only tags devices that have KEY_Q (code 16) to avoid tagging the
# touchscreen as a keyboard.

# Capabilities are at the parent inputN level, not eventN
CAPS="$1/../capabilities"

[ -f "$CAPS/key" ] || exit 0

# KEY_Q is bit 16 = 0x10000 in the last (rightmost) word of the bitmap.
LAST_WORD=$(cat "$CAPS/key" | tr ' ' '\n' | tail -1)
Q_BIT=$(( 0x$LAST_WORD & 0x10000 ))

if [ "$Q_BIT" -ne 0 ]; then
  echo ID_INPUT=1
  echo ID_INPUT_KEY=1
  echo ID_INPUT_KEYBOARD=1
fi
