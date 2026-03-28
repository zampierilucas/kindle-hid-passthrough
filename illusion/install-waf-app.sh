#!/bin/sh
#
# install-waf-app.sh - Install BTManager WAF app (Illusion)
# Run this on the Kindle to register and set up the BTManager WAF app
#

APP_ID="com.lzampier.btmanager"
APP_DIR="/mnt/us/kindle_hid_passthrough/illusion/BTManager"
ILLUSION_DIR="/mnt/us/kindle_hid_passthrough/illusion"
SOURCE_DIR="$APP_DIR"
PYTHON="/mnt/us/python3.10-kindle/python3-wrapper.sh"
MAIN_PY="$ILLUSION_DIR/../main.py"
SCRIPTLET="$ILLUSION_DIR/BTManager.sh"
SCRIPTLET_DEST="/mnt/us/documents/BTManager.sh"
APPREG_DB="/var/local/appreg.db"

echo ""
echo "=== BTManager Installer ==="
echo ""

# ---- Check prerequisites ----

if [ ! -f "$SOURCE_DIR/config.xml" ]; then
    echo "ERROR: App files not found at $SOURCE_DIR"
    echo "Make sure kindle_hid_passthrough is installed first."
    exit 1
fi

if [ ! -f "$MAIN_PY" ]; then
    echo "ERROR: main.py not found at $MAIN_PY"
    exit 1
fi

# ---- Install WAF app ----

echo "1. Checking WAF app files..."
if [ ! -d "$APP_DIR" ]; then
    echo "   ERROR: App directory not found at $APP_DIR"
    echo "   Deploy kindle_hid_passthrough first."
    exit 1
fi
echo "   Files at $APP_DIR"

# ---- Make helper executable ----

echo "2. Setting permissions..."
chmod +x "$SCRIPTLET"
echo "   Done"

# ---- Register in appreg.db ----

echo "3. Registering app..."
if [ -f "$APPREG_DB" ]; then
    existing=$(sqlite3 "$APPREG_DB" "SELECT handlerId FROM handlerIds WHERE handlerId='$APP_ID';" 2>/dev/null)
    if [ -z "$existing" ]; then
        sqlite3 "$APPREG_DB" <<EOF
INSERT OR IGNORE INTO handlerIds (handlerId) VALUES ('$APP_ID');
INSERT OR IGNORE INTO associations (handlerId, interface, contentId, defaultAssoc)
    VALUES ('$APP_ID', 'application', 'GL:$APP_ID', 0);
INSERT OR IGNORE INTO properties (handlerId, name, value)
    VALUES ('$APP_ID', 'lipcId', '$APP_ID');
INSERT OR IGNORE INTO properties (handlerId, name, value)
    VALUES ('$APP_ID', 'appId', '$APP_ID');
INSERT OR IGNORE INTO properties (handlerId, name, value)
    VALUES ('$APP_ID', 'command', '/usr/bin/mesquite -l $APP_ID -c file://$APP_DIR/');
INSERT OR IGNORE INTO properties (handlerId, name, value)
    VALUES ('$APP_ID', 'unloadPolicy', 'unloadOnPause');
INSERT OR IGNORE INTO properties (handlerId, name, value)
    VALUES ('$APP_ID', 'extend-start', 'Y');
INSERT OR IGNORE INTO properties (handlerId, name, value)
    VALUES ('$APP_ID', 'supportedOrientation', 'U');
EOF
        echo "   Registered $APP_ID in appreg.db"
    else
        echo "   Already registered"
    fi
else
    echo "   WARNING: appreg.db not found at $APPREG_DB"
fi

# ---- Install scriptlet ----

echo "4. Installing scriptlet..."
cp "$SCRIPTLET" "$SCRIPTLET_DEST"
chmod +x "$SCRIPTLET_DEST"
echo "   Installed to $SCRIPTLET_DEST"

# ---- Start helper ----

echo "5. Starting daemon..."
# Stop existing instances
pkill -f 'main.py --daemon' 2>/dev/null
sleep 1
"$PYTHON" "$MAIN_PY" --daemon &
sleep 1
echo "   Daemon started"

echo ""
echo "=== Installation Complete ==="
echo ""
echo "You can now:"
echo "  - Open 'BT Manager' from the Kindle library (scriptlet)"
echo "  - Or launch directly: lipc-set-prop com.lab126.appmgrd start app://$APP_ID"
echo ""
echo "To start on boot, install the upstart config:"
echo "  cp $ILLUSION_DIR/../hid-passthrough-dev.upstart /etc/upstart/hid-passthrough.conf"
echo ""
