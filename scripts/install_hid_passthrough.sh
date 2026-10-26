#!/bin/sh
# Name: Install Kindle HID Passthrough
# Author: Lucas Zampieri

TARBALL=/tmp/kindle-hid-passthrough-armv7.tar.xz
RELEASE_DIR=/mnt/us/khp-release

echo "Downloading latest release..."
if ! curl -fL -o "$TARBALL" https://github.com/zampierilucas/kindle-hid-passthrough/releases/latest/download/kindle-hid-passthrough-armv7.tar.xz; then
    echo "Download failed. Check your Wi-Fi connection and run this again."
    rm -f "$TARBALL"
    exit 0
fi

rm -rf "$RELEASE_DIR"
mkdir -p "$RELEASE_DIR"

echo "Extracting files..."
if ! tar -xJf "$TARBALL" -C "$RELEASE_DIR"; then
    echo "Extraction failed. Run this again to retry."
    rm -f "$TARBALL"
    exit 0
fi

rm -f "$TARBALL"

echo "Installing Kindle HID Passthrough..."
if ! sh "$RELEASE_DIR/scripts/install.sh" installAll; then
    echo "Installation failed. See the output above and run this again."
    exit 0
fi

echo "HID passthrough installed, cleaning up..."
sleep 3
rm -f /mnt/us/documents/install_hid_passthrough.sh
