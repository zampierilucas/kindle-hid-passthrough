#!/bin/sh
# Name: Install Kindle HID Passthrough
# Author: Lucas Zampieri

echo "Downloading latest release..."
if ! curl -fL -o /mnt/us/documents/kindle-hid-passthrough-armv7.tar.xz https://github.com/zampierilucas/kindle-hid-passthrough/releases/latest/download/kindle-hid-passthrough-armv7.tar.xz; then
    echo "Download failed. Check your Wi-Fi connection and run this again."
    rm -f /mnt/us/documents/kindle-hid-passthrough-armv7.tar.xz
    exit 0
fi
mkdir -p /mnt/us/khp-release
echo "Extracting files..."
tar -xJf /mnt/us/documents/kindle-hid-passthrough-armv7.tar.xz -C /mnt/us/khp-release
echo "Installing Kindle HID Passthrough..."
sh /mnt/us/khp-release/scripts/install.sh installAll
echo "HID passthrough installed, cleaning up..."
sleep 3
rm -f /mnt/us/documents/kindle-hid-passthrough-armv7.tar.xz
rm -f /mnt/us/documents/install_hid_passthrough.sh
