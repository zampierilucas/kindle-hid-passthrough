#!/bin/sh

trap '/usr/sbin/mntroot ro 2>/dev/null' EXIT
trap 'exit 130' INT TERM HUP

INSTALL_DIR="/mnt/us/kindle_hid_passthrough"
MAPPER_DIR="/mnt/us/kindle-button-mapper"
APP_ID="com.lzampier.btmanager"
APPREG_DB="/var/local/appreg.db"
SCRIPTLET_DEST="/mnt/us/documents/BTManager.sh"
KUAL_DIR="/mnt/us/extensions/kindle-hid-passthrough"
KUAL_LOG="/tmp/kindle-hid-kual.log"
FBINK="/mnt/us/koreader/fbink"

MENU="installAll|Install or update everything (recommended)|yes
pairDevice|Pair Bluetooth keyboard|no
listDevices|List paired devices|no
installUdevRules|Install udev rules (keyboard service)|yes
installUpstart|Install upstart (auto-start on boot)|yes
installWAFApp|Install BTManager app|yes
installKOReaderPlugin|Install KOReader plugin|yes
installButtonMapper|Install Button Mapper (gamepad mapping)|yes
installKUAL|Install KUAL menu entry|no
uninstallAll|Uninstall everything|yes
removeUpstart|Disable auto-start on boot (remove upstart)|yes"

SRC_DIR=$(cd "$(dirname "$0")/.." && pwd)

# True when the tree is already sitting at its destination, so the copies below
# would be a no-op. Probe with a sentinel instead of comparing path strings,
# /mnt/us is case-insensitive and also reachable through the /mnt/base-us alias
# mount, and a false negative here would delete the source before copying it.
SAME_DIR=0
SENTINEL=".khp-install-probe.$$"
mkdir -p "$INSTALL_DIR" 2>/dev/null
if [ -d "$INSTALL_DIR" ] && true > "$INSTALL_DIR/$SENTINEL" 2>/dev/null; then
  [ -e "$SRC_DIR/$SENTINEL" ] && SAME_DIR=1
  rm -f "$INSTALL_DIR/$SENTINEL"
fi

in_install_dir()
{
  [ "$SAME_DIR" = 1 ]
}

daemonRunning()
{
  pgrep -f "ld-linux-armhf." >/dev/null 2>&1 || \
    pgrep -f "main.py --daemon" >/dev/null 2>&1
}

stopDaemon()
{
  echo " -> Stopping daemon"
  lipc-set-prop com.lab126.appmgrd start app://com.lab126.booklet.home 2>/dev/null
  /sbin/stop hid-passthrough 2>/dev/null
  pkill -f "kindle-hid-passthrough --daemon" 2>/dev/null
  pkill -f "main.py --daemon" 2>/dev/null
  pkill -f "ld-linux-armhf." 2>/dev/null

  # dist/ld-linux-armhf.so.3 stays busy while the loader runs, and writing to a
  # busy binary fails with ETXTBSY, so wait for it to go before copying over it.
  i=0
  while [ "$i" -lt 15 ]; do
    daemonRunning || return 0
    sleep 1
    i=$((i + 1))
  done
  echo " -> WARNING: daemon is still running, files may not update cleanly"
}

startDaemon()
{
  daemonRunning && return 0
  echo " -> Starting daemon"
  if [ -f /etc/upstart/hid-passthrough.conf ] && \
     /sbin/start hid-passthrough >/dev/null 2>&1; then
    return 0
  fi
  (cd "$INSTALL_DIR" && ./kindle-hid-passthrough --daemon >/dev/null 2>&1 &)
}

# mesquite caches the app's html and js, without this the UI stays on the old version.
clearWafCache()
{
  rm -rf "/var/local/mesquite/$APP_ID" /var/local/mesquite/BTManager 2>/dev/null
}

# Files that shipped in earlier releases and would otherwise be left behind when
# the release is unpacked straight over the install dir.
removeStaleFiles()
{
  rm -f "$INSTALL_DIR/scripts/setlayout.sh" \
        "$INSTALL_DIR/assets/menu_setlayout.json" \
        "$INSTALL_DIR/koreader-plugin/hidpassthrough.koplugin/event_map_keyboard.lua" \
        /usr/local/bin/dev_is_keyboard.sh 2>/dev/null
}

koreaderPluginDir()
{
  for base in /mnt/us/koreader /mnt/base-us/koreader; do
    if [ -d "$base/plugins" ]; then
      echo "$base/plugins"
      return 0
    fi
  done
  return 1
}

installMainFiles()
{
  echo " -> Installing main program files"
  mkdir -p "$INSTALL_DIR/cache"
  if in_install_dir; then
    removeStaleFiles
    chmod +x "$INSTALL_DIR/kindle-hid-passthrough"
    echo " -> Running from the install directory, program files left as they are."
    echo " -> Ready."
    return 0
  fi

  if [ ! -f "$SRC_DIR/dist/main.bin" ]; then
    echo "ERROR: release files not found at $SRC_DIR" >&2
    echo "       Run this script from the extracted release, not a partial copy." >&2
    return 1
  fi

  # Replaced outright rather than merged, files dropped between releases would
  # otherwise linger and still get loaded.
  rm -rf "$INSTALL_DIR/dist" "$INSTALL_DIR/scripts" "$INSTALL_DIR/assets" \
         "$INSTALL_DIR/koreader-plugin"
  mkdir -p "$INSTALL_DIR/dist"
  cp -r "$SRC_DIR/dist/"* "$INSTALL_DIR/dist/"
  cp -r "$SRC_DIR/scripts" "$SRC_DIR/assets" "$INSTALL_DIR/"
  if [ -d "$SRC_DIR/koreader-plugin" ]; then
    cp -r "$SRC_DIR/koreader-plugin" "$INSTALL_DIR/"
  fi
  cp "$SRC_DIR/kindle-hid-passthrough" "$INSTALL_DIR/"
  cp "$SRC_DIR/libsyscall_wrapper.so" "$INSTALL_DIR/"

  if [ -f "$INSTALL_DIR/config.ini" ]; then
    cp "$SRC_DIR/config.ini" "$INSTALL_DIR/config.ini.new"
    echo " -> Kept your config.ini, new defaults written to config.ini.new"
  else
    cp "$SRC_DIR/config.ini" "$INSTALL_DIR/"
  fi

  removeStaleFiles
  chmod +x "$INSTALL_DIR/kindle-hid-passthrough"
  echo " -> Ready."
}

installAll()
{
  echo ""
  if [ -f "$INSTALL_DIR/kindle-hid-passthrough" ]; then
    echo "=== Install / Update ==="
    echo "Existing install found at $INSTALL_DIR, updating it in place."
  else
    echo "=== Full Install ==="
  fi

  stopDaemon
  if ! installMainFiles; then
    echo ""
    echo "Install FAILED: main program files were not installed."
    startDaemon
    return 1
  fi
  installUdevRules
  # Auto-start is opt-in, only refresh a job the user already enabled.
  if [ -f /etc/upstart/hid-passthrough.conf ]; then
    installUpstart
  fi
  installWAFApp
  installKUAL
  installButtonMapper
  if ! installKOReaderPlugin; then
    startDaemon
    echo ""
    echo "Install finished WITH ERRORS: the KOReader plugin was not installed."
    return 1
  fi
  startDaemon
  echo ""
  echo "Installation complete. Open 'BT Manager' from the Kindle library."
}

installUdevRules()
{
  echo " -> Installing udev rules"
  /usr/sbin/mntroot rw
  cp "$SRC_DIR/assets/99-hid-keyboard.rules" /etc/udev/rules.d
  /usr/sbin/udevadm control --reload-rules
  /usr/sbin/mntroot ro
  echo " -> Ready."
}

screenAlert()
{
  title=$(printf '%s' "$1" | sed 's/"/\\"/g')
  text=$(printf '%s' "$2" | sed 's/"/\\"/g')
  lipc-set-prop com.lab126.pillow pillowAlert "{ \"clientParams\":{ \"alertId\":\"appAlert1\", \"show\":true, \"customStrings\":[ { \"matchStr\":\"alertTitle\", \"replaceStr\":\"$title\" }, { \"matchStr\":\"alertText\", \"replaceStr\":\"$text\" } ] } }" 2>/dev/null
}

kualRun()
{
  [ -x "$FBINK" ] && "$FBINK" -q -c >/dev/null 2>&1
  "$1" 2>&1 | tee "$KUAL_LOG" | {
    row=2
    while IFS= read -r line; do
      [ -x "$FBINK" ] || continue
      [ "$row" -gt 55 ] && { "$FBINK" -q -c >/dev/null 2>&1; row=2; }
      "$FBINK" -q -y "$row" "$line" >/dev/null 2>&1
      row=$((row + 1))
    done
  }
  screenAlert "HID Passthrough" "$(tail -n 1 "$KUAL_LOG")"
}

kualMenu()
{
  printf '{"items":[{"name":"Bluetooth HID passthrough","priority":0,"items":['
  printf '{"name":"Start daemon","priority":1,'
  printf '"action":"%s/scripts/hid-passthrough-daemon.sh","params":"start"},' "$INSTALL_DIR"
  printf '{"name":"Stop daemon","priority":2,'
  printf '"action":"%s/scripts/hid-passthrough-daemon.sh","params":"stop"},' "$INSTALL_DIR"
  printf '{"name":"Install","priority":3,"items":['
  echo "$MENU" | while IFS='|' read -r action label in_kual; do
    [ "$in_kual" = yes ] || continue
    priority=$((priority + 1))
    printf '%s{"name":"%s","priority":%d,"action":"%s/scripts/install.sh",' \
      "$separator" "$label" "$priority" "$INSTALL_DIR"
    printf '"params":"kualRun %s","exitmenu":false,"internal":"status %s . . ."}' \
      "$action" "$label"
    separator=","
  done
  printf ']}]}]}\n'
}

installKUAL()
{
  if [ ! -d /mnt/us/extensions ]; then
    echo " -> KUAL not found, skipping menu entry"
    return 0
  fi
  echo " -> Installing KUAL menu entry"
  mkdir -p "$KUAL_DIR"
  cp "$SRC_DIR/assets/config.xml" "$KUAL_DIR/"
  kualMenu > "$KUAL_DIR/menu.json"
  echo " -> Ready."
}

installUpstart()
{
  echo " -> Installing upstart service"
  rm -f "$INSTALL_DIR/boot_attempts"
  /usr/sbin/mntroot rw
  cp "$SRC_DIR/assets/hid-passthrough.upstart" /etc/upstart/hid-passthrough.conf
  /usr/sbin/mntroot ro
  # upstart only picks up a newly dropped .conf after a config reload, without
  # this the job stays unknown and the start below fails until a reboot.
  /sbin/initctl reload-configuration 2>/dev/null || true
  echo " -> Ready."
}

removeUpstart()
{
  echo " -> Removing upstart service"
  /usr/sbin/mntroot rw
  rm -f /etc/upstart/hid-passthrough.conf
  /usr/sbin/mntroot ro
  /sbin/initctl reload-configuration 2>/dev/null || true
  echo " -> Ready."
}

pairDevice()
{
  (cd "$INSTALL_DIR" && ./kindle-hid-passthrough --pair 2>&1 | grep -v "libenvload.so")
}

listDevices()
{
  cat "$INSTALL_DIR/devices.conf"
}

installWAFApp()
{
  echo " -> Installing BTManager app"
  if ! in_install_dir; then
    rm -rf "$INSTALL_DIR/illusion"
    mkdir -p "$INSTALL_DIR/illusion"
    cp -r "$SRC_DIR/illusion/." "$INSTALL_DIR/illusion/"
  fi
  clearWafCache
  if [ -f "$INSTALL_DIR/illusion/install-waf-app.sh" ]; then
    /bin/sh "$INSTALL_DIR/illusion/install-waf-app.sh"
  else
    echo "ERROR: $INSTALL_DIR/illusion/install-waf-app.sh not found"
    return 1
  fi
}

# Installs into its own directory with its own upstart job, so an existing
# standalone install is updated rather than duplicated, and it keeps working if
# this one is removed. Its install.sh runs under `set -e` and ends by poking
# upstart, which fails on a Kindle that never had the job, so a non-zero exit
# here is a warning and not a failed install.
installButtonMapper()
{
  if [ ! -f "$SRC_DIR/button-mapper/install.sh" ]; then
    echo " -> Button Mapper not bundled in this build, skipping"
    return 0
  fi
  echo " -> Installing Button Mapper"
  if /bin/sh "$SRC_DIR/button-mapper/install.sh"; then
    echo " -> Ready."
  else
    echo " -> WARNING: Button Mapper install failed, gamepad mapping will be unavailable"
  fi
  return 0
}

installKOReaderPlugin()
{
  PLUGINS_DIR=$(koreaderPluginDir) || {
    echo " -> KOReader not found, skipping plugin install"
    return 0
  }
  SRC_PLUGIN="$SRC_DIR/koreader-plugin/hidpassthrough.koplugin"
  for f in main.lua _meta.lua event_map_extra.lua mapper.lua koreader_actions.lua; do
    if [ ! -f "$SRC_PLUGIN/$f" ]; then
      echo "ERROR: $f is missing from $SRC_PLUGIN" >&2
      echo "       Run this script from the extracted release, not a partial copy." >&2
      return 1
    fi
  done

  echo " -> Installing KOReader plugin into $PLUGINS_DIR"
  DEST="$PLUGINS_DIR/hidpassthrough.koplugin"
  rm -rf "$DEST"
  if ! cp -r "$SRC_PLUGIN" "$DEST"; then
    echo "ERROR: failed to copy the plugin to $DEST" >&2
    return 1
  fi
  echo " -> Ready. Restart KOReader to load it."
}

uninstallAll()
{
  echo ""
  echo "=== Uninstall ==="
  printf "This will stop the daemon, remove udev/upstart/WAF app, Button Mapper, and delete the install directory.\n"
  printf "Your paired devices (devices.conf) and pairing keys (cache/) are kept.\n"
  # Only prompt when there is someone to answer. Package managers run this
  # without a tty and have already asked in their own UI.
  if [ -t 0 ]; then
    printf "Continue? [y/N]: "
    read confirm
    case "$confirm" in
      y|Y|yes|YES) ;;
      *) echo "Aborted."; return ;;
    esac
  fi

  stopDaemon

  /usr/sbin/mntroot rw

  echo " -> Removing upstart config"
  rm -f /etc/upstart/hid-passthrough.conf

  # The audio switch installs and removes the wrapper itself. This is the
  # net for uninstalling with the switch still on, which never runs the
  # teardown script.
  echo " -> Removing GST audio wrapper"
  if [ -f /usr/bin/gst-launch-0.10.real ]; then
    mv /usr/bin/gst-launch-0.10.real /usr/bin/gst-launch-0.10
  fi

  echo " -> Removing udev rules"
  rm -f /etc/udev/rules.d/99-hid-keyboard.rules
  if [ -f /usr/local/bin/dev_is_keyboard.sh ]; then
    rm -f /usr/local/bin/dev_is_keyboard.sh
  fi
  /usr/sbin/udevadm control --reload-rules 2>/dev/null

  echo " -> Unregistering WAF app"
  clearWafCache
  if [ -f "$APPREG_DB" ]; then
    sqlite3 "$APPREG_DB" <<EOF 2>/dev/null
DELETE FROM properties WHERE handlerId='$APP_ID';
DELETE FROM associations WHERE handlerId='$APP_ID';
DELETE FROM handlerIds WHERE handlerId='$APP_ID';
EOF
  fi
  rm -f "$SCRIPTLET_DEST"

  echo " -> Purging WAF cache"
  # Graceful appmgrd unload, not pkill (pkill makes appmgrd report a crash).
  lipc-set-prop com.lab126.appmgrd stop "app://$APP_ID" 2>/dev/null
  MESQUITE_DIR="/var/local/mesquite"
  if [ -d "$MESQUITE_DIR" ]; then
    for d in "$MESQUITE_DIR"/*[Bb][Tt][Mm]anager* "$MESQUITE_DIR/BT Manager" "$MESQUITE_DIR/$APP_ID"; do
      [ -e "$d" ] || continue
      rm -rf "$d"
    done
  fi

  /usr/sbin/mntroot ro

  uninstallButtonMapper

  if PLUGINS_DIR=$(koreaderPluginDir); then
    echo " -> Removing KOReader plugin"
    rm -rf "$PLUGINS_DIR/hidpassthrough.koplugin"
  fi

  echo " -> Removing KUAL menu entry"
  rm -rf "$KUAL_DIR"

  echo " -> Removing install directory $INSTALL_DIR, keeping devices.conf and cache/"
  cd /tmp
  for entry in "$INSTALL_DIR"/* "$INSTALL_DIR"/.[!.]*; do
    [ -e "$entry" ] || continue
    case "${entry##*/}" in
      devices.conf|cache) continue ;;
    esac
    rm -rf "$entry"
  done

  echo ""
  echo "Uninstall complete. Reboot recommended."
}

# Button Mapper is the mapping backend now, not an optional extra, so it goes
# with everything else. Its own uninstaller owns the upstart job, the WAF app
# and the install dir, so defer to it rather than duplicating any of that.
uninstallButtonMapper()
{
  if [ ! -f "$MAPPER_DIR/uninstall.sh" ]; then
    return 0
  fi
  echo " -> Removing Button Mapper"
  if /bin/sh "$MAPPER_DIR/uninstall.sh" >/dev/null 2>&1; then
    echo " -> Ready."
  else
    echo " -> WARNING: Button Mapper uninstall failed, remove $MAPPER_DIR by hand"
  fi
  return 0
}

menu_count()
{
  echo "$MENU" | wc -l
}

print_menu()
{
  printf "\nSelect an option:\n"
  i=0
  echo "$MENU" | while IFS='|' read -r action label kual; do
    i=$((i + 1))
    printf "%2d) %s\n" "$i" "$label"
  done
  printf "%2d) Quit\n" "$(($(menu_count) + 1))"
}

# Non-interactive entry point: `sh install.sh <action>` runs one action and exits.
if [ $# -gt 0 ]; then
  case "$1" in
    update) installAll; exit $? ;;
    kualRun)
      echo "$MENU" | cut -d'|' -f1 | grep -qx "$2" || { echo "Unknown action: $2" >&2; exit 1; }
      kualRun "$2"; exit $? ;;
    installAll|installUdevRules|installUpstart|removeUpstart|installMainFiles| \
    installWAFApp|installKUAL|installKOReaderPlugin|installButtonMapper| \
    uninstallButtonMapper|uninstallAll|kualMenu)
      "$1"; exit $? ;;
    *) echo "Unknown action: $1" >&2; exit 1 ;;
  esac
fi

while :; do
  print_menu
  count=$(menu_count)
  printf "Enter choice [1-%d]: " "$((count + 1))"
  read choice || break
  case "$choice" in
    ''|*[!0-9]*)
      printf "Invalid option: %s\n" "$choice"
      continue
      ;;
  esac
  if [ "$choice" -ge 1 ] && [ "$choice" -le "$count" ]; then
    "$(echo "$MENU" | sed -n "${choice}p" | cut -d'|' -f1)"
  elif [ "$choice" -eq "$((count + 1))" ]; then
    echo "Exiting."
    break
  else
    printf "Invalid option: %s\n" "$choice"
  fi
done
