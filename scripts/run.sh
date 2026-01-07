#!/bin/sh
# Kindle HID Passthrough - Self-extracting launcher
# Extracts to persistent location and runs from there

INSTALL_DIR="/mnt/us/hid-passthrough"
PYTHON="${KINDLE_PYTHON:-/mnt/us/python3.10-kindle/bin/python3.10}"

# Get the directory where this script is running (temp extraction dir)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# If we're in a temp dir, copy to persistent location
if echo "$SCRIPT_DIR" | grep -q "^/tmp\|^/var/tmp"; then
    echo "Installing to $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR"
    cp -rL --no-preserve=mode,ownership "$SCRIPT_DIR"/* "$INSTALL_DIR/" 2>/dev/null || \
        cp -rL "$SCRIPT_DIR"/* "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/run.sh" 2>/dev/null || true
    # Run from installed location
    SCRIPT_DIR="$INSTALL_DIR"
fi

# Add our lib directory to Python path
export PYTHONPATH="${SCRIPT_DIR}/lib:${PYTHONPATH}"

# Set base path for config discovery
export KINDLE_HID_BASE="${SCRIPT_DIR}"

# Run the main module
exec "$PYTHON" -m kindle_hid_passthrough.main "$@"
