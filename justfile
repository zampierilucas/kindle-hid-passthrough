# Justfile for Kindle HID Passthrough
# Usage: just <recipe>

src_dir := justfile_directory()
remote_dir := "/mnt/us/kindle_hid_passthrough"
waf_dir := "/mnt/us/kindle_hid_passthrough/illusion/BTManager"
upstart_conf := "/etc/upstart/hid-passthrough.conf"
log_file := "/var/log/hid_passthrough.log"
python := "/mnt/us/python3.10-kindle/python3-wrapper.sh"

# Target Kindle SSH host (override: `just host=mykindle deploy`, or set KINDLE_HOST)
host := env_var_or_default("KINDLE_HOST", "kindle")

default:
    @just --list

# Deploy to Kindle over SSH and start API server
deploy:
    @echo "Deploying to Kindle..."
    @just host={{host}} kill
    @echo "Writing build SHA..."
    git -C {{src_dir}} rev-parse --short HEAD > {{src_dir}}/kindle_hid_passthrough/BUILD_SHA
    @echo "Remounting filesystems as writable..."
    ssh {{host}} "/usr/sbin/mntroot rw && mount -o remount,rw /mnt/base-us"
    @echo "Copying all files via tar pipe..."
    (cd {{src_dir}} && tar cf - \
        --transform='s|^kindle_hid_passthrough/hid-passthrough-dev.upstart|etc/upstart/hid-passthrough.conf|' \
        --transform='s|^kindle_hid_passthrough/|mnt/us/kindle_hid_passthrough/|' \
        --transform='s|^assets/99-hid-keyboard.rules|etc/udev/rules.d/99-hid-keyboard.rules|' \
        --transform='s|^assets/|mnt/us/kindle_hid_passthrough/assets/|' \
        --transform='s|^scripts/|mnt/us/kindle_hid_passthrough/scripts/|' \
        --transform='s|^illusion/BTManager/|mnt/us/kindle_hid_passthrough/illusion/BTManager/|' \
        --transform='s|^illusion/BTManager.sh|mnt/us/kindle_hid_passthrough/illusion/BTManager.sh|' \
        kindle_hid_passthrough/*.py \
        kindle_hid_passthrough/config.ini \
        kindle_hid_passthrough/BUILD_SHA \
        kindle_hid_passthrough/hid-passthrough-dev.upstart \
        kindle_hid_passthrough/modules/*.ko \
        assets/99-hid-keyboard.rules \
        assets/hid-passthrough.upstart \
        scripts/dev_is_keyboard.sh \
        scripts/install.sh \
        illusion/BTManager/* \
        illusion/BTManager.sh \
    ) | ssh {{host}} "tar xf - -C /"
    -ssh {{host}} "udevadm control --reload-rules" 2>/dev/null || true
    @echo "Clearing Python bytecode cache..."
    ssh {{host}} "rm -rf {{remote_dir}}/__pycache__"
    @echo "Creating cache directory..."
    ssh {{host}} "mkdir -p {{remote_dir}}/cache"
    @echo "Clearing WAF cache..."
    -ssh {{host}} "rm -rf /var/local/mesquite/com.lzampier.btmanager /var/local/mesquite/BTManager" 2>/dev/null
    @just host={{host}} register-waf
    @echo "Starting API server..."
    @just host={{host}} server
    ssh {{host}} 'lipc-set-prop com.lab126.appmgrd start app://com.lzampier.btmanager'
    @echo "Deployment complete!"

# Register BTManager WAF app in appreg.db and install scriptlet (idempotent)
register-waf:
    @echo "Registering BTManager WAF app..."
    ssh {{host}} 'APP_ID="com.lzampier.btmanager"; \
        APP_DIR="{{remote_dir}}/illusion/BTManager"; \
        SCRIPTLET="{{remote_dir}}/illusion/BTManager.sh"; \
        chmod +x "$SCRIPTLET" 2>/dev/null; \
        sqlite3 /var/local/appreg.db "INSERT OR IGNORE INTO interfaces (interface) VALUES (\"application\"); \
            INSERT OR IGNORE INTO handlerIds (handlerId) VALUES (\"$APP_ID\"); \
            INSERT OR IGNORE INTO associations (handlerId, interface, contentId, defaultAssoc) VALUES (\"$APP_ID\", \"application\", \"GL:$APP_ID\", 0); \
            INSERT OR REPLACE INTO properties (handlerId, name, value) VALUES (\"$APP_ID\", \"lipcId\", \"$APP_ID\"); \
            INSERT OR REPLACE INTO properties (handlerId, name, value) VALUES (\"$APP_ID\", \"command\", \"/usr/bin/mesquite -l $APP_ID -c file://$APP_DIR/\"); \
            INSERT OR REPLACE INTO properties (handlerId, name, value) VALUES (\"$APP_ID\", \"supportedOrientation\", \"U\");"; \
        cp "$SCRIPTLET" /mnt/us/documents/BTManager.sh && chmod +x /mnt/us/documents/BTManager.sh'

# Kill daemon and close WAF app
kill:
    -ssh {{host}} 'lipc-set-prop com.lab126.appmgrd start app://com.lab126.booklet.home 2>/dev/null; \
        /sbin/initctl stop hid-passthrough 2>/dev/null; \
        pkill -9 -f "main.py --daemon" 2>/dev/null; \
        pkill -9 -f daemon.py 2>/dev/null; \
        true'
    @echo "All processes stopped."

# Start daemon + API server
server:
    -ssh {{host}} "pkill -9 -f 'main.py --daemon'" 2>/dev/null || true
    ssh {{host}} "sleep 2 && /mnt/us/python3.10-kindle/python3-wrapper.sh /mnt/us/kindle_hid_passthrough/main.py --daemon > /dev/null 2>&1 &"
    @echo "Daemon + API starting (takes ~8s on Kindle)."

# Check daemon status
status:
    ssh {{host}} "/sbin/initctl status hid-passthrough"

# View daemon logs
logs:
    ssh {{host}} "tail -f {{log_file}}"

# View recent logs
logs-recent:
    ssh {{host}} "tail -n 50 {{log_file}}"

# Restart daemon
restart:
    ssh {{host}} "/sbin/initctl restart hid-passthrough"

# Stop daemon
stop:
    ssh {{host}} "/sbin/initctl stop hid-passthrough"

# Start daemon
start:
    ssh {{host}} "/sbin/initctl start hid-passthrough"

# Clear cache
clear-cache:
    ssh {{host}} "rm -rf {{remote_dir}}/cache/*.json"
    @echo "Cache cleared!"

# Show cache
show-cache:
    ssh {{host}} "ls -lh {{remote_dir}}/cache/ 2>/dev/null || echo 'Empty'"

# Show configured devices
devices:
    @ssh {{host}} "cat {{remote_dir}}/devices.conf 2>/dev/null || echo 'No devices configured'"

# Edit devices.conf
edit-devices:
    ssh {{host}} "vi {{remote_dir}}/devices.conf"

# Show pairing keys
keys:
    @ssh {{host}} "[ -f {{remote_dir}}/cache/pairing_keys.json ] \
        && {{python}} -m json.tool {{remote_dir}}/cache/pairing_keys.json \
        || echo 'No pairing keys'"

# Print a read-only diagnostics dump for bug reports
diagnostics:
    @ssh {{host}} "{{python}} {{remote_dir}}/main.py --diagnostics"

# SSH into Kindle
ssh:
    ssh {{host}}

# Check Python syntax
check:
    python3 -m py_compile {{src_dir}}/kindle_hid_passthrough/*.py
    @echo "All files compile OK!"

# Run local unit tests (no Kindle required)
test:
    python3 {{src_dir}}/tests/test_hci_parser.py
    python3 {{src_dir}}/tests/test_cpu_latency.py
    python3 {{src_dir}}/tests/test_power_policy.py

# Run mock API server for local WAF app testing
mock-server:
    python3 {{src_dir}}/tests/mock_api_server.py

# Deploy and follow logs
deploy-watch: deploy
    @just host={{host}} logs

# Pair a new device (Classic)
pair-classic:
    ssh {{host}} "{{python}} {{remote_dir}}/main.py --pair --protocol classic"

# Pair a new device (BLE)
pair-ble:
    ssh {{host}} "{{python}} {{remote_dir}}/main.py --pair --protocol ble"

# Run manually (for debugging)
run:
    ssh {{host}} "{{python}} {{remote_dir}}/main.py"

# Deploy KOReader plugin to Kindle
deploy-koreader:
    @echo "Deploying KOReader plugin..."
    ssh {{host}} "rm -rf /mnt/us/koreader/plugins/hidpassthrough.koplugin"
    (cd {{src_dir}} && tar cf - \
        --transform='s|^koreader-plugin/hidpassthrough.koplugin/|mnt/us/koreader/plugins/hidpassthrough.koplugin/|' \
        koreader-plugin/hidpassthrough.koplugin/ \
    ) | ssh {{host}} "tar xf - -C /"
    @echo "KOReader plugin deployed!"

# Remove autostart (removes upstart config)
remove-autostart:
    @echo "Removing autostart..."
    ssh {{host}} "/usr/sbin/mntroot rw"
    ssh {{host}} "rm -f {{upstart_conf}}"
    @echo "Autostart removed."

# --- Install from pre-built tarball ---

repo := "zampierilucas/kindle-hid-passthrough"
artifact_name := "kindle-hid-passthrough-armv7"
tarball_name := "kindle-hid-passthrough-armv7.tar.gz"

# Install onto Kindle from a GitHub release (latest, version, or local tarball path)
install-release source="":
    #!/usr/bin/env bash
    set -euo pipefail
    source="{{source}}"
    if [ -f "$source" ]; then
        tarball="$source"
        echo "Installing from local tarball: $tarball"
    else
        tmpdir=$(mktemp -d)
        trap 'rm -rf "$tmpdir"' EXIT
        version="$source"
        if [ -z "$version" ]; then
            echo "Fetching latest release..."
            version=$(curl -sfL "https://api.github.com/repos/{{repo}}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
            if [ -z "$version" ]; then
                echo "ERROR: Could not determine latest release version" >&2
                exit 1
            fi
        fi
        echo "Downloading release $version..."
        curl -sfL -o "$tmpdir/{{tarball_name}}" \
            "https://github.com/{{repo}}/releases/download/${version}/{{tarball_name}}"
        tarball="$tmpdir/{{tarball_name}}"
    fi
    echo "Installing to Kindle..."
    just host={{host}} kill
    ssh {{host}} "/usr/sbin/mntroot rw && mount -o remount,rw /mnt/base-us"
    ssh {{host}} "mkdir -p {{remote_dir}}"
    cat "$tarball" | ssh {{host}} "tar xzf - -C {{remote_dir}}"
    ssh {{host}} "cd {{remote_dir}} && sh scripts/install.sh installAll"
    ssh {{host}} "/usr/sbin/mntroot ro"
    ssh {{host}} "/sbin/initctl start hid-passthrough"
    ssh {{host}} 'lipc-set-prop com.lab126.appmgrd start app://com.lzampier.btmanager'
    echo "Install complete!"

# Install from latest CI build artifact
install-ci branch="main":
    #!/usr/bin/env bash
    set -euo pipefail
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT
    echo "Finding latest successful CI run on {{branch}}..."
    run_id=$(gh run list \
        --repo "{{repo}}" \
        --workflow build-arm.yml \
        --branch "{{branch}}" \
        --status success \
        --limit 1 \
        --json databaseId \
        --jq '.[0].databaseId')
    if [ -z "$run_id" ] || [ "$run_id" = "null" ]; then
        echo "ERROR: No successful CI run found on branch '{{branch}}'" >&2
        exit 1
    fi
    echo "Downloading artifact from run $run_id..."
    gh run download "$run_id" \
        --repo "{{repo}}" \
        --name "{{artifact_name}}" \
        --dir "$tmpdir"
    tarball=$(find "$tmpdir" -name "{{tarball_name}}" -print -quit)
    if [ -z "$tarball" ]; then
        echo "ERROR: Tarball not found in downloaded artifact" >&2
        ls -la "$tmpdir"/
        exit 1
    fi
    just host={{host}} install-release "$tarball"

# Bump __version__, commit to main, tag, and push (usage: just version-bump 3.3.5)
version-bump version:
    #!/usr/bin/env bash
    set -euo pipefail
    version="{{version}}"
    if ! echo "$version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "ERROR: version must be X.Y.Z (got: $version)" >&2
        exit 1
    fi
    cd {{src_dir}}
    if [ -n "$(git status --porcelain)" ]; then
        echo "ERROR: working tree not clean" >&2
        exit 1
    fi
    branch=$(git rev-parse --abbrev-ref HEAD)
    if [ "$branch" != "main" ]; then
        echo "ERROR: must be on main (got: $branch)" >&2
        exit 1
    fi
    git pull --ff-only origin main
    sed -i -E "s/^__version__ = \".*\"/__version__ = \"$version\"/" kindle_hid_passthrough/config.py
    if ! grep -q "^__version__ = \"$version\"$" kindle_hid_passthrough/config.py; then
        echo "ERROR: failed to update version in config.py" >&2
        exit 1
    fi
    git add kindle_hid_passthrough/config.py
    git commit -s -m "chore: bump version to $version"
    git tag "v$version"
    git push origin main
    git push origin "v$version"
    echo "Bumped to $version and pushed tag v$version"

# Uninstall system integration (upstart, udev, WAF app) but leave code in place
uninstall:
    @echo "Uninstalling system integration..."
    @just host={{host}} kill
    @echo "Remounting filesystems as writable..."
    ssh {{host}} "/usr/sbin/mntroot rw"
    @echo "Removing upstart config..."
    -ssh {{host}} "rm -f {{upstart_conf}}"
    @echo "Removing udev rules..."
    -ssh {{host}} "rm -f /etc/udev/rules.d/99-hid-keyboard.rules"
    -ssh {{host}} "/usr/sbin/udevadm control --reload-rules"
    @echo "Removing legacy helper script (pre-/mnt/us layout)..."
    -ssh {{host}} "[ -f /usr/local/bin/dev_is_keyboard.sh ] && rm -f /usr/local/bin/dev_is_keyboard.sh"
    @echo "Removing WAF app scriptlet..."
    -ssh {{host}} "rm -f /mnt/us/documents/BTManager.sh"
    @echo "Remounting read-only..."
    -ssh {{host}} "/usr/sbin/mntroot ro"
    @echo "Uninstall complete. Code left at {{remote_dir}}/"
