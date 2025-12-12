#!/bin/bash
# Build ARM binary for Kindle BLE HID using Docker + QEMU
# This creates a self-contained executable that can run on the Kindle

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building ARM binary for Kindle BLE HID..."
echo "This will take 15-30 minutes due to QEMU emulation"
echo ""

# Build the Docker image and compile with Nuitka
# Note: docker build doesn't support --cpus/--memory flags
# Resource limits are controlled by daemon config or at runtime
docker build \
    --network=host \
    --platform linux/arm/v7 \
    -f Dockerfile.arm \
    -t kindle-ble-hid-builder \
    .

echo ""
echo "Build complete! Extracting binary..."
echo ""

# Create output directory
mkdir -p dist

# Extract the binary from the container
CONTAINER_ID=$(docker create kindle-ble-hid-builder)
docker cp "$CONTAINER_ID:/build/kindle-ble-hid" ./dist/
docker rm "$CONTAINER_ID"

echo "ARM binary created at: ./dist/kindle-ble-hid"
echo ""

# Show binary info
file ./dist/kindle-ble-hid
ls -lh ./dist/kindle-ble-hid

echo ""
echo "To deploy to Kindle:"
echo "  scp ./dist/kindle-ble-hid kindle:/mnt/us/bumble_ble_hid/"
