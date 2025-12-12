#!/bin/bash
# Build ARM hard-float binary for Kindle HID Passthrough using Docker + QEMU
# This creates a self-contained executable that can run on the Kindle

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building ARM hard-float binary for Kindle HID Passthrough..."
echo "This will take 15-30 minutes due to QEMU emulation"
echo ""

# Build the Docker image and compile with Nuitka
docker build \
    --network=host \
    --platform linux/arm/v7 \
    -f Dockerfile.arm \
    -t kindle-hid-passthrough-builder \
    .

echo ""
echo "Build complete! Extracting binary..."
echo ""

# Create output directory
mkdir -p dist

# Extract the binary from the container
CONTAINER_ID=$(docker create kindle-hid-passthrough-builder)
docker cp "$CONTAINER_ID:/build/kindle-hid-passthrough" ./dist/
docker rm "$CONTAINER_ID"

echo "ARM binary created at: ./dist/kindle-hid-passthrough"
echo ""

# Show binary info
file ./dist/kindle-hid-passthrough
ls -lh ./dist/kindle-hid-passthrough

echo ""
echo "To deploy to Kindle:"
echo "  scp ./dist/kindle-hid-passthrough kindle:/mnt/us/kindle_hid_passthrough/"
