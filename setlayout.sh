#!/bin/sh

DISPLAY="${DISPLAY:-:0}"
CUR="/tmp/current.xkb"
NEW="/tmp/patched.xkb"

restore() {
  if [ -f "$CUR" ]; then
    xkbcomp -I"$XKB_BASE" "$CUR" "$DISPLAY"
    echo "Restored previous keymap from $CUR to $DISPLAY"
  else
    echo "No saved map at $CUR" >&2
    exit 1
  fi
}

if [ "${1:-}" = "--restore" ]; then
  restore
  exit 0
fi

if [ $# -lt 1 ]; then
  echo "usage: $0 <layout-or-variant>   (e.g. fr, de, 'fr(oss)')" >&2
  echo "       $0 --restore" >&2
  exit 1
fi

xkbcomp -xkb "$DISPLAY" "$CUR"

awk -v include_str="pc+$1" '
  BEGIN { skipping=0; depth=0; replaced=0 }
  # match start of xkb_symbols block (optionally named)
  /^xkb_symbols([[:space:]]+"[^"]+")?[[:space:]]*\{/ {
      if (!replaced) {
          print "xkb_symbols {";
          print "  include \"" include_str "\"";  # NOTE: no semicolon on purpose
          print "};";
          skipping=1; depth=1; replaced=1; next
      }
  }
  skipping {
      # strip quoted strings so brace counting is correct
      line=$0
      gsub(/"([^"\\]|\\.)*"/, "", line)
      # count braces
      ob=gsub(/\{/, "{", line)
      cb=gsub(/\}/, "}", line)
      depth += ob - cb
      if (depth <= 0) skipping=0
      next
  }
  { print }
  END {
      if (!replaced) {
          # no symbols block existed — append one
          print ""
          print "xkb_symbols {"
          print "  include \"" include_str "\""
          print "};"
      }
  }
' "$CUR" > "$NEW"

xkbcomp -I/usr/share/X11/xkb "$NEW" "$DISPLAY"

echo "Loaded layout: \"$1\" on display $DISPLAY"
echo "Rollback copy saved at $CUR (use \"$0 --restore\" to revert)"
