#!/bin/sh

installAll()
{
  echo ""
  echo "=== Full Install ==="
  installUdevRules
  installUpstart
  installWAFApp
  echo ""
  echo "Installation complete. Open 'BT Manager' from the Kindle library."
}

installUdevRules()
{
  echo " -> Installing udev rules"
  mntroot rw
  cp assets/dev_is_keyboard.sh /usr/local/bin/
  cp assets/99-hid-keyboard.rules /etc/udev/rules.d
  udevadm control --reload-rules
  mntroot ro
  echo " -> Ready."
}

installUpstart()
{
  echo " -> Installing upstart service"
  mntroot rw
  cp kindle_hid_passthrough/hid-passthrough.upstart /etc/upstart/hid-passthrough.conf
  mntroot ro
  echo " -> Ready."
}

pairDevice()
{
  lipc-set-prop -s com.lab126.btfd BTenable 0:1
  ./kindle-hid-passthrough --pair
}

listDevices()
{
  cat devices.conf
}

setLayout()
{
  printf "Enter layout code (e.g. fr, de, 'fr(oss)'): "
  read layout
  /bin/sh setlayout.sh "$layout"
}

installWAFApp()
{
  if [ -f illusion/install-waf-app.sh ]; then
    /bin/sh illusion/install-waf-app.sh
  else
    echo "ERROR: illusion/install-waf-app.sh not found"
  fi
}

print_menu()
{
  printf "\nSelect an option:\n"
  printf " 1) Install everything (recommended)\n"
  printf " 2) Pair Bluetooth keyboard\n"
  printf " 3) List paired devices\n"
  printf " 4) Install udev rules (keyboard service)\n"
  printf " 5) Install upstart (auto-start on boot)\n"
  printf " 6) Install BTManager app\n"
  printf " 7) Set custom keyboard layout\n"
  printf " 8) Quit\n"
}

while :; do
  print_menu
  printf "Enter choice [1-8]: "
  read choice
  case "$choice" in
    1)
      installAll
      ;;
    2)
      pairDevice
      ;;
    3)
      listDevices
      ;;
    4)
      installUdevRules
      ;;
    5)
      installUpstart
      ;;
    6)
      installWAFApp
      ;;
    7)
      setLayout
      ;;
    8)
      echo "Exiting."
      break
      ;;
    *)
      printf "Invalid option: %s\n" "$choice"
      ;;
  esac
done
