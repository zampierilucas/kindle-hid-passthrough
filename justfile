# Justfile for Kindle HID Passthrough
# Usage: just <recipe>

src_dir := justfile_directory()
remote_dir := "/mnt/us/kindle_hid_passthrough"
waf_dir := "/mnt/us/kindle_hid_passthrough/illusion/BTManager"
upstart_conf := "/etc/upstart/hid-passthrough.conf"
log_file := "/var/log/hid_passthrough.log"
python := "/mnt/us/python3.10-kindle/python3-wrapper.sh"

default:
    @just --list

# Deploy to Kindle over SSH and start API server
deploy:
    @echo "Deploying to Kindle..."
    @just kill
    @echo "Remounting filesystems as writable..."
    ssh kindle "/usr/sbin/mntroot rw && mount -o remount,rw /mnt/base-us"
    @echo "Copying all files via tar pipe..."
    (cd {{src_dir}} && tar cf - \
        --transform='s|^kindle_hid_passthrough/hid-passthrough-dev.upstart|etc/upstart/hid-passthrough.conf|' \
        --transform='s|^kindle_hid_passthrough/|mnt/us/kindle_hid_passthrough/|' \
        --transform='s|^assets/99-hid-keyboard.rules|etc/udev/rules.d/99-hid-keyboard.rules|' \
        --transform='s|^assets/dev_is_keyboard.sh|usr/local/bin/dev_is_keyboard.sh|' \
        --transform='s|^illusion/BTManager/|mnt/us/kindle_hid_passthrough/illusion/BTManager/|' \
        kindle_hid_passthrough/*.py \
        kindle_hid_passthrough/config.ini \
        kindle_hid_passthrough/hid-passthrough-dev.upstart \
        assets/99-hid-keyboard.rules \
        assets/dev_is_keyboard.sh \
        illusion/BTManager/* \
    ) | ssh kindle "tar xf - -C /"
    ssh kindle "chmod +x /usr/local/bin/dev_is_keyboard.sh"
    -ssh kindle "udevadm control --reload-rules" 2>/dev/null || true
    @echo "Clearing Python bytecode cache..."
    ssh kindle "rm -rf {{remote_dir}}/__pycache__"
    @echo "Creating cache directory..."
    ssh kindle "mkdir -p {{remote_dir}}/cache"
    @echo "Starting API server..."
    @just server
    @echo "Deployment complete! Open BTManager app on Kindle."

# Kill daemon and close WAF app
kill:
    -ssh kindle 'lipc-set-prop com.lab126.appmgrd start app://com.lab126.booklet.home 2>/dev/null; \
        /sbin/initctl stop hid-passthrough 2>/dev/null; \
        pkill -9 -f "main.py --daemon" 2>/dev/null; \
        pkill -9 -f daemon.py 2>/dev/null; \
        true'
    @echo "All processes stopped."

# Start daemon + API server
server:
    -ssh kindle "pkill -9 -f 'main.py --daemon'" 2>/dev/null || true
    ssh kindle "sleep 2 && /mnt/us/python3.10-kindle/python3-wrapper.sh /mnt/us/kindle_hid_passthrough/main.py --daemon > /dev/null 2>&1 &"
    @echo "Daemon + API starting (takes ~8s on Kindle)."

# Check daemon status
status:
    ssh kindle "/sbin/initctl status hid-passthrough"

# View daemon logs
logs:
    ssh kindle "tail -f {{log_file}}"

# View recent logs
logs-recent:
    ssh kindle "tail -n 50 {{log_file}}"

# Restart daemon
restart:
    ssh kindle "/sbin/initctl restart hid-passthrough"

# Stop daemon
stop:
    ssh kindle "/sbin/initctl stop hid-passthrough"

# Start daemon
start:
    ssh kindle "/sbin/initctl start hid-passthrough"

# Clear cache
clear-cache:
    ssh kindle "rm -rf {{remote_dir}}/cache/*.json"
    @echo "Cache cleared!"

# Show cache
show-cache:
    ssh kindle "ls -lh {{remote_dir}}/cache/ 2>/dev/null || echo 'Empty'"

# Show configured devices
devices:
    @ssh kindle "cat {{remote_dir}}/devices.conf 2>/dev/null || echo 'No devices configured'"

# Edit devices.conf
edit-devices:
    ssh kindle "vi {{remote_dir}}/devices.conf"

# Show pairing keys
keys:
    @ssh kindle "cat {{remote_dir}}/cache/pairing_keys.json 2>/dev/null | python3 -m json.tool || echo 'No pairing keys'"

# SSH into Kindle
ssh:
    ssh kindle

# Check Python syntax
check:
    python3 -m py_compile {{src_dir}}/kindle_hid_passthrough/*.py
    @echo "All files compile OK!"

# Run mock API server for local WAF app testing
mock-server:
    python3 {{src_dir}}/tests/mock_api_server.py

# Open BTManager WAF app on Kindle
open-waf:
    ssh kindle 'lipc-set-prop com.lab126.appmgrd start app://com.lzampier.btmanager'

# Deploy and open WAF app
deploy-waf: deploy
    @sleep 8
    @just open-waf

# Deploy and follow logs
deploy-watch: deploy
    @just logs

# Pair a new device (Classic)
pair-classic:
    ssh kindle "{{python}} {{remote_dir}}/main.py --pair --protocol classic"

# Pair a new device (BLE)
pair-ble:
    ssh kindle "{{python}} {{remote_dir}}/main.py --pair --protocol ble"

# Run manually (for debugging)
run:
    ssh kindle "{{python}} {{remote_dir}}/main.py"

# Remove autostart (removes upstart config)
remove-autostart:
    @echo "Removing autostart..."
    ssh kindle "/usr/sbin/mntroot rw"
    ssh kindle "rm -f {{upstart_conf}}"
    @echo "Autostart removed."
