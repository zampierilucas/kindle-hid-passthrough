/**
 * BTManager - Bluetooth HID Passthrough Manager
 * ES5 compatible - WebKit 533
 *
 * Communicates with api_server.py HTTP server on localhost:8321
 */

var BTManager = (function() {
    "use strict";

    var HELPER_URL = "http://localhost:8321";
    var POLL_INTERVAL = 3000;
    var MESSAGE_TIMEOUT = 4000;
    var LOG_VIEW_MAX_CHARS = 6000;

    var pollTimer = null;
    var messageTimer = null;
    var confirmAction = null;
    var confirmAddr = null;
    var lastStatus = null;
    var lastStatusJson = "";
    var isScanning = false;
    var isPairing = false;
    var scanPollTimer = null;
    var pairPollTimer = null;
    var logPollTimer = null;
    var logsVisible = false;
    var pairLogTimer = null;
    var btOn = false;
    var autostartOn = false;
    var scanResultCount = 0;

    // Currently viewed device in detail overlay
    var detailDevice = null;
    var detailRenderKey = "";

    // ---- XHR Helper ----

    function request(path, callback) {
        var xhr = new XMLHttpRequest();
        var url = HELPER_URL + path;
        var timedOut = false;
        var done = false;

        var timeout = setTimeout(function() {
            timedOut = true;
            if (!done) {
                xhr.abort();
                callback(null, "Request timed out");
            }
        }, 8000);

        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4) {
                done = true;
                clearTimeout(timeout);
                if (timedOut) return;
                if (xhr.status === 200) {
                    var data = null;
                    try {
                        data = JSON.parse(xhr.responseText);
                    } catch (e) {
                        callback(null, "Invalid JSON response");
                        return;
                    }
                    callback(data, null);
                } else {
                    callback(null, "HTTP " + xhr.status);
                }
            }
        };

        try {
            xhr.open("GET", url, true);
            xhr.send(null);
        } catch (e) {
            done = true;
            clearTimeout(timeout);
            callback(null, "Connection failed");
        }
    }

    // ---- UI Helpers ----

    function getEl(id) {
        return document.getElementById(id);
    }

    function pressBtn(el) {
        if (typeof el === "string") el = getEl(el);
        if (el) el.className += " btn-active";
    }

    function releaseBtn(el) {
        if (typeof el === "string") el = getEl(el);
        if (el) el.className = el.className.replace(/ ?btn-active/g, "");
    }

    function showMessage(text, isError) {
        var bar = getEl("messageBar");
        setText(bar, text);
        bar.className = "message-bar visible" + (isError ? " error" : "");
        if (messageTimer) clearTimeout(messageTimer);
        messageTimer = setTimeout(function() {
            bar.className = "message-bar";
        }, MESSAGE_TIMEOUT);
    }

    // Daemon log lines reach this page verbatim. They carry ANSI colour escapes
    // and can carry C0/C1 control bytes, neither of which escapeHtml touches and
    // both of which corrupt the WebKit view this runs in.
    function sanitizeText(str) {
        if (str === null || str === undefined) return "";
        str = String(str);
        str = str.replace(/\x1b\[[0-?]*[ -\/]*[@-~]/g, "");
        return str.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/g, "");
    }

    function escapeHtml(str) {
        str = sanitizeText(str);
        if (!str) return "";
        return str.replace(/&/g, "&amp;")
                  .replace(/</g, "&lt;")
                  .replace(/>/g, "&gt;")
                  .replace(/"/g, "&quot;");
    }

    // Assign log text as a text node rather than markup. escapeHtml is enough for
    // correctness, but a text node cannot be reinterpreted as markup at all, which
    // is the property worth having for content the page does not author.
    function setText(el, text) {
        if (!el) return;
        text = sanitizeText(text);
        while (el.firstChild) {
            el.removeChild(el.firstChild);
        }
        el.appendChild(document.createTextNode(text));
    }

    // Cap what the viewer holds. The log endpoint is polled every few seconds and
    // the oldest lines are the least interesting, so keep the tail.
    function renderLogLines(lines) {
        if (!lines) return "";
        var text = sanitizeText(lines.join("\n"));
        if (text.length > LOG_VIEW_MAX_CHARS) {
            text = text.slice(text.length - LOG_VIEW_MAX_CHARS);
        }
        return text;
    }

    function getConnections(status) {
        return (status && status.connections) ? status.connections : [];
    }

    function findConnection(status, addr) {
        if (!addr) return null;
        var conns = getConnections(status);
        for (var i = 0; i < conns.length; i++) {
            if (conns[i].address &&
                    conns[i].address.toUpperCase() === addr.toUpperCase()) {
                return conns[i];
            }
        }
        return null;
    }
    // ---- Toggle ----

    function setToggleUI(on) {
        btOn = on;
        var toggle = getEl("btnToggle");
        if (on) {
            toggle.className = "toggle on";
        } else {
            toggle.className = "toggle";
        }
        getEl("mainContent").style.display = on ? "block" : "none";
        getEl("offState").style.display = on ? "none" : "block";
    }

    function toggleBluetooth() {
        if (btOn) {
            showMessage("Turning off...", false);
            request("/stop", function(data, err) {
                if (err) {
                    showMessage("Error: " + err, true);
                    return;
                }
                if (data && data.ok) {
                    setToggleUI(false);
                    showMessage("Bluetooth off", false);
                } else {
                    showMessage(data && data.error ? data.error : "Failed", true);
                }
                lastStatusJson = "";
                setTimeout(updateStatus, 1000);
            });
        } else {
            showMessage("Turning on...", false);
            request("/start", function(data, err) {
                if (err) {
                    showMessage("Error: " + err, true);
                    return;
                }
                if (data && data.ok) {
                    setToggleUI(true);
                    showMessage("Bluetooth on", false);
                } else {
                    showMessage(data && data.error ? data.error : "Failed", true);
                }
                lastStatusJson = "";
                setTimeout(updateStatus, 1500);
            });
        }
    }

    // ---- Autostart ----

    function setAutostartUI(on) {
        autostartOn = on;
        getEl("btnAutostart").className = on ? "toggle on" : "toggle";
    }

    function toggleAutostart() {
        var want = autostartOn ? "0" : "1";
        showMessage(autostartOn ? "Disabling autostart..." : "Enabling autostart...", false);
        request("/autostart?enable=" + want, function(data, err) {
            if (err) {
                showMessage("Error: " + err, true);
                return;
            }
            setAutostartUI(!!(data && data.enabled));
            if (data && data.ok) {
                showMessage(data.enabled ? "Starts on boot" : "Won't start on boot", false);
            } else {
                showMessage(data && data.error ? data.error : "Failed", true);
            }
            lastStatusJson = "";
        });
    }

    // ---- Status Polling ----

    function updateStatus() {
        request("/status", function(data, err) {
            if (err) {
                setToggleUI(false);
                lastStatusJson = "";
                return;
            }

            var json = JSON.stringify(data);
            if (json === lastStatusJson) return;
            lastStatusJson = json;

            var running = data.daemon_running;
            setToggleUI(running);

            var conns = getConnections(data);
            renderDeviceLists(data.devices, conns);

            var hidMissing = false;
            for (var i = 0; i < conns.length; i++) {
                if (conns[i].hid_ready === false) hidMissing = true;
            }
            getEl("hidWarning").style.display = hidMissing ? "block" : "none";

            if (data.version) {
                getEl("footerVersion").innerHTML = "v" + escapeHtml(data.version);
            }

            setAutostartUI(!!data.autostart);

            lastStatus = data;

            renderDeviceDetail();
        });
    }

    // ---- Device Lists (3-tier) ----

    function renderDeviceLists(devices, connections) {
        var connectedAddrs = {};
        var i;
        for (i = 0; i < connections.length; i++) {
            if (connections[i].address) {
                connectedAddrs[connections[i].address.toUpperCase()] = true;
            }
        }

        var connected = [];
        var paired = [];
        var listed = {};

        if (devices) {
            for (i = 0; i < devices.length; i++) {
                var dev = devices[i];
                var key = dev.address ? dev.address.toUpperCase() : "";
                listed[key] = true;
                if (key && connectedAddrs[key]) {
                    connected.push(dev);
                } else {
                    paired.push(dev);
                }
            }
        }

        // Connections with no devices.conf entry (wildcard or keystore-only)
        for (i = 0; i < connections.length; i++) {
            var conn = connections[i];
            var ckey = conn.address ? conn.address.toUpperCase() : "";
            if (ckey && !listed[ckey]) {
                connected.push({
                    address: conn.address,
                    protocol: conn.protocol,
                    name: conn.name
                });
            }
        }

        // Connected section
        var connSection = getEl("connectedSection");
        var connList = getEl("connectedList");
        if (connected.length > 0) {
            connSection.style.display = "block";
            connList.innerHTML = renderDeviceRows(connected, true);
        } else {
            connSection.style.display = "none";
        }

        // Paired section
        var pairedSection = getEl("pairedSection");
        var pairedList = getEl("pairedList");
        if (paired.length > 0) {
            pairedSection.style.display = "block";
            pairedList.innerHTML = renderDeviceRows(paired, false);
        } else {
            pairedSection.style.display = "none";
        }
    }

    function renderDeviceRows(devices, isConnected) {
        var html = "";
        for (var i = 0; i < devices.length; i++) {
            var dev = devices[i];
            var addr = escapeHtml(dev.address || "");
            var proto = escapeHtml(dev.protocol || "");
            var name = escapeHtml(dev.name || "") || addr;

            html += '<div class="device-row" data-addr="' + addr + '" data-proto="' + proto + '" data-name="' + escapeHtml(dev.name || "") + '">';
            html += '<span class="device-row-chevron">&#x276F;</span>';
            html += '<div class="device-row-name' + (isConnected ? '' : ' idle') + '">' + name + '</div>';
            html += '<div class="device-row-sub">' + proto.toUpperCase() + '</div>';
            html += '</div>';
        }
        return html;
    }

    // ---- Device Detail Overlay ----

    function showDeviceDetail(addr, proto, name) {
        detailDevice = { addr: addr, proto: proto, name: name, connected: false };
        detailRenderKey = "";
        window.scrollTo(0, 0);
        renderDeviceDetail();
        getEl("deviceOverlay").className = "device-overlay visible";
    }

    function renderDeviceDetail() {
        if (!detailDevice) return;

        var conn = findConnection(lastStatus, detailDevice.addr);
        var isConnected = conn !== null;
        detailDevice.connected = isConnected;

        var uhid = conn ? (conn.uhid_name || "") : "";
        var inputs = conn && conn.input_paths ? conn.input_paths.join(", ") : "";
        var hidReady = conn ? conn.hid_ready : null;

        var key = [isConnected ? "1" : "0", String(hidReady), uhid, inputs,
                   detailDevice.name, detailDevice.proto].join("|");
        if (key === detailRenderKey) return;
        detailRenderKey = key;

        getEl("detailName").innerHTML = escapeHtml(detailDevice.name) || escapeHtml(detailDevice.addr);
        getEl("detailStatus").innerHTML = isConnected ? "&#x25CF; Connected" : "&#x25CB; Not Connected";
        getEl("detailProtocol").innerHTML = escapeHtml(detailDevice.proto).toUpperCase();
        getEl("detailAddress").innerHTML = escapeHtml(detailDevice.addr);
        getEl("btnDetailAction").innerHTML = isConnected ? "Disconnect" : "Connect";

        var hidSection = getEl("detailHid");
        var hidWarn = getEl("detailHidWarning");
        hidSection.style.display = "none";
        hidWarn.style.display = "none";

        if (isConnected) {
            if (hidReady === false) {
                hidWarn.style.display = "block";
                getEl("detailUhid").innerHTML = "--";
                getEl("detailInputPaths").innerHTML = "--";
                hidSection.style.display = "block";
            } else if (uhid || inputs) {
                getEl("detailUhid").innerHTML = escapeHtml(uhid) || "--";
                getEl("detailInputPaths").innerHTML = escapeHtml(inputs) || "--";
                hidSection.style.display = "block";
            }
        }
    }

    function hideDeviceDetail() {
        getEl("deviceOverlay").className = "device-overlay";
        detailDevice = null;
        detailRenderKey = "";
    }

    function detailAction() {
        if (!detailDevice) return;
        if (detailDevice.connected) {
            showMessage("Disconnecting...", false);
            request("/disconnect?addr=" + encodeURIComponent(detailDevice.addr), function(data, err) {
                if (err) {
                    showMessage("Error: " + err, true);
                    return;
                }
                if (data && data.ok) {
                    showMessage("Disconnected", false);
                    hideDeviceDetail();
                } else {
                    showMessage(data && data.error ? data.error : "Failed", true);
                }
                lastStatusJson = "";
                setTimeout(updateStatus, 1000);
            });
        } else {
            showMessage("Connecting...", false);
            var url = "/connect?addr=" + encodeURIComponent(detailDevice.addr);
            if (detailDevice.proto) url += "&protocol=" + encodeURIComponent(detailDevice.proto);
            request(url, function(data, err) {
                if (err) {
                    showMessage("Error: " + err, true);
                    return;
                }
                if (data && data.ok) {
                    showMessage("Connecting...", false);
                    hideDeviceDetail();
                } else {
                    showMessage(data && data.error ? data.error : "Failed", true);
                }
                lastStatusJson = "";
                setTimeout(updateStatus, 2000);
            });
        }
    }

    function detailRemove() {
        if (!detailDevice) return;
        confirmAddr = detailDevice.addr;
        showConfirm(
            "Remove device?<br/><span class=\"dialog-addr\">" + escapeHtml(detailDevice.addr) + "</span>",
            "remove"
        );
    }

    function removeDevice(addr) {
        showMessage("Removing...", false);
        request("/remove?addr=" + encodeURIComponent(addr), function(data, err) {
            releaseBtn("dialogConfirmBtn");
            if (err) {
                showMessage("Error: " + err, true);
                return;
            }
            if (data && data.ok) {
                showMessage("Device removed", false);
                hideDeviceDetail();
            } else {
                showMessage(data && data.error ? data.error : "Failed", true);
            }
            lastStatusJson = "";
            setTimeout(updateStatus, 500);
        });
    }

    // ---- Scan ----

    function startScan() {
        if (isScanning || isPairing) return;
        isScanning = true;

        var btn = getEl("btnScan");
        btn.innerHTML = "Stop Scan";
        btn.className = "btn btn-scan scanning";

        scanResultCount = 0;
        getEl("availableSection").style.display = "block";
        getEl("scanIndicator").innerHTML = "Scanning...";
        getEl("availableList").innerHTML = "";

        request("/scan", function(data, err) {
            if (err) {
                showMessage("Scan error: " + err, true);
                resetScanUI();
                return;
            }
            pollScanStatus();
        });
    }

    function stopScan() {
        request("/scan-stop", function() {});
        resetScanUI();
        if (scanResultCount === 0) {
            getEl("availableSection").style.display = "none";
        }
    }

    function toggleScan() {
        if (isScanning) {
            stopScan();
        } else {
            startScan();
        }
    }

    function pollScanStatus() {
        scanPollTimer = setTimeout(function() {
            request("/scan-status", function(data, err) {
                if (err) {
                    showMessage("Scan error: " + err, true);
                    resetScanUI();
                    return;
                }
                if (data && data.scanning) {
                    if (data.devices && data.devices.length > 0) {
                        renderAvailableDevices(data.devices);
                    }
                    pollScanStatus();
                    return;
                }
                // Scan complete
                resetScanUI();
                if (data && data.ok && data.devices) {
                    if (data.devices.length > 0) {
                        renderAvailableDevices(data.devices);
                    } else {
                        getEl("availableSection").style.display = "none";
                        showMessage("No HID devices found", false);
                    }
                } else {
                    showMessage(data && data.error ? data.error : "Scan failed", true);
                }
            });
        }, 2000);
    }

    function resetScanUI() {
        isScanning = false;
        var btn = getEl("btnScan");
        btn.innerHTML = "Scan for Devices";
        btn.className = "btn btn-scan";
        getEl("scanIndicator").innerHTML = "";
        if (scanPollTimer) {
            clearTimeout(scanPollTimer);
            scanPollTimer = null;
        }
    }

    function renderAvailableDevices(devices) {
        var container = getEl("availableList");
        scanResultCount = devices ? devices.length : 0;
        if (!devices || devices.length === 0) {
            container.innerHTML = '<div class="device-empty">No devices found</div>';
            return;
        }

        var html = "";
        for (var i = 0; i < devices.length; i++) {
            var dev = devices[i];
            var addr = escapeHtml(dev.address || "");
            var name = escapeHtml(dev.name || "Unknown");
            var proto = escapeHtml(dev.protocol || "ble");

            html += '<div class="available-row">';
            html += '<button class="btn-pair" data-addr="' + addr + '" data-proto="' + proto + '" data-name="' + name + '">Pair</button>';
            html += '<div class="available-name">' + name + '</div>';
            html += '<div class="available-sub">' + proto.toUpperCase() + '</div>';
            html += '</div>';
        }

        container.innerHTML = html;
    }

    // ---- Pair (unchanged logic) ----

    function startPair(addr, protocol, name) {
        if (isPairing) return;
        if (isScanning) {
            request("/scan-stop", function() {});
            resetScanUI();
        }
        isPairing = true;

        window.scrollTo(0, 0);
        getEl("pairMessage").innerHTML = "Pairing...";
        getEl("pairAddr").innerHTML = escapeHtml(addr);
        setText(getEl("pairLogContent"), "");
        getEl("pairOverlay").className = "pair-overlay visible";
        pollPairLogs();

        var url = "/pair?addr=" + encodeURIComponent(addr) + "&protocol=" + encodeURIComponent(protocol);
        if (name) url += "&name=" + encodeURIComponent(name);
        request(url, function(data, err) {
            if (err) {
                showMessage("Pair error: " + err, true);
                resetPairUI();
                return;
            }
            pollPairStatus();
        });
    }

    function pollPairStatus() {
        pairPollTimer = setTimeout(function() {
            request("/pair-status", function(data, err) {
                if (err) {
                    showMessage("Pair error: " + err, true);
                    resetPairUI();
                    return;
                }
                if (data && data.pairing) {
                    getEl("pairMessage").innerHTML = "Pairing in progress...";
                    pollPairStatus();
                    return;
                }
                resetPairUI();
                if (data && data.ok) {
                    showMessage("Paired: " + (data.address || ""), false);
                    getEl("availableList").innerHTML = "";
                    getEl("availableSection").style.display = "none";
                    updateStatus();
                } else {
                    showMessage(data && data.error ? data.error : "Pairing failed", true);
                }
            });
        }, 2000);
    }

    function cancelPair() {
        pressBtn("btnPairClose");
        resetPairUI();
        showMessage("Pairing cancelled", false);
    }

    function resetPairUI() {
        isPairing = false;
        getEl("pairOverlay").className = "pair-overlay";
        if (pairPollTimer) {
            clearTimeout(pairPollTimer);
            pairPollTimer = null;
        }
        if (pairLogTimer) {
            clearTimeout(pairLogTimer);
            pairLogTimer = null;
        }
    }

    function pollPairLogs() {
        request("/logs?lines=20", function(data, err) {
            if (!isPairing) return;
            if (data && data.lines) {
                var viewer = getEl("pairLogContent");
                setText(viewer, renderLogLines(data.lines));
                var container = viewer.parentNode;
                container.scrollTop = container.scrollHeight;
            }
            if (isPairing) {
                pairLogTimer = setTimeout(pollPairLogs, 2000);
            }
        });
    }

    // ---- Log Viewer (unchanged) ----

    function showLogs() {
        logsVisible = true;
        window.scrollTo(0, 0);
        getEl("logOverlay").className = "log-overlay visible";
        fetchLogs();
    }

    function hideLogs() {
        logsVisible = false;
        getEl("logOverlay").className = "log-overlay";
        if (logPollTimer) {
            clearTimeout(logPollTimer);
            logPollTimer = null;
        }
    }

    function scrollLogsUp() {
        var viewer = getEl("logViewer");
        viewer.scrollTop = Math.max(0, viewer.scrollTop - 400);
    }

    function scrollLogsDown() {
        var viewer = getEl("logViewer");
        viewer.scrollTop = viewer.scrollTop + 400;
    }

    function fetchLogs() {
        request("/logs?lines=100", function(data, err) {
            if (err) {
                setText(getEl("logContent"), "Error loading logs: " + err);
                return;
            }
            if (data && data.lines) {
                setText(getEl("logContent"), renderLogLines(data.lines));
                var viewer = getEl("logViewer");
                viewer.scrollTop = viewer.scrollHeight;
            }
            if (logsVisible) {
                logPollTimer = setTimeout(fetchLogs, 3000);
            }
        });
    }

    // ---- Cache ----

    function clearCache() {
        showMessage("Clearing cache...", false);
        request("/clear-cache", function(data, err) {
            releaseBtn("dialogConfirmBtn");
            if (err) {
                showMessage("Error: " + err, true);
                return;
            }
            if (data && data.ok) {
                var msg = "Cache cleared";
                if (data.files_removed) {
                    msg += " (" + data.files_removed + " files)";
                }
                showMessage(msg, false);
            } else {
                showMessage(data && data.error ? data.error : "Failed", true);
            }
        });
    }

    // ---- Confirm Dialog ----

    function showConfirm(message, action) {
        getEl("dialogMessage").innerHTML = message;
        getEl("confirmOverlay").className = "overlay visible";
        confirmAction = action;
    }

    function confirmOk() {
        pressBtn("dialogConfirmBtn");
        getEl("confirmOverlay").className = "overlay";
        if (confirmAction === "remove" && confirmAddr) {
            removeDevice(confirmAddr);
        } else if (confirmAction === "cache") {
            clearCache();
        }
        confirmAction = null;
        confirmAddr = null;
    }

    function confirmCancel() {
        getEl("confirmOverlay").className = "overlay";
        confirmAction = null;
        confirmAddr = null;
    }

    // ---- Event Binding ----

    function bindBtn(id, fn) {
        var el = getEl(id);
        if (el) el.addEventListener("click", fn, false);
    }

    function bindEvents() {
        bindBtn("btnToggle", toggleBluetooth);
        bindBtn("btnAutostart", toggleAutostart);
        bindBtn("btnScan", toggleScan);
        bindBtn("footerDebug", showLogs);
        bindBtn("btnDetailClose", hideDeviceDetail);
        bindBtn("btnDetailAction", detailAction);
        bindBtn("btnDetailRemove", detailRemove);
        bindBtn("btnPairClose", cancelPair);
        bindBtn("btnLogClose", hideLogs);
        bindBtn("btnLogUp", scrollLogsUp);
        bindBtn("btnLogDown", scrollLogsDown);
        bindBtn("btnClearCache", function() {
            showConfirm("Clear all cached HID descriptors?", "cache");
        });

        // Clear placeholder on first tap for keyboard test area
        var testInput = getEl("keyboardTest");
        if (testInput) {
            var cleared = false;
            testInput.addEventListener("focus", function() {
                if (!cleared) {
                    testInput.innerHTML = "";
                    cleared = true;
                }
            }, false);
        }

        bindBtn("dialogCancelBtn", confirmCancel);
        bindBtn("dialogConfirmBtn", confirmOk);

        // Event delegation for dynamically created elements
        document.addEventListener("click", function(e) {
            var target = e.target;
            if (!target) return;
            var addr, proto, name;

            // Pair button in available list (check BEFORE device row walk-up)
            if (target.className && target.className.indexOf("btn-pair") !== -1) {
                addr = target.getAttribute("data-addr");
                proto = target.getAttribute("data-proto");
                name = target.getAttribute("data-name");
                if (addr) startPair(addr, proto || "ble", name || "");
                return;
            }

            // Device row tap -> detail overlay
            var row = target;
            while (row && row !== document) {
                if (row.className && row.className.indexOf("device-row") !== -1 && row.getAttribute("data-addr")) {
                    addr = row.getAttribute("data-addr");
                    proto = row.getAttribute("data-proto");
                    name = row.getAttribute("data-name");
                    showDeviceDetail(addr, proto, name);
                    return;
                }
                row = row.parentNode;
            }
        }, false);

        // Kindle swipe gestures for page scrolling
        if (typeof kindle !== "undefined" && kindle.gestures) {
            kindle.gestures.onswipe = function(direction) {
                var step = 500;
                if (logsVisible) {
                    if (direction === "up") scrollLogsDown();
                    else if (direction === "down") scrollLogsUp();
                } else {
                    var y = (window.pageYOffset || document.documentElement.scrollTop || 0);
                    if (direction === "up") {
                        window.scrollTo(0, y + step);
                    } else if (direction === "down") {
                        window.scrollTo(0, Math.max(0, y - step));
                    }
                }
            };
        }

        // Mousewheel scrolling (for connected keyboards)
        window.addEventListener("mousewheel", function(e) {
            e.preventDefault();
            if (logsVisible) {
                var viewer = getEl("logViewer");
                if (e.wheelDeltaY > 0) {
                    viewer.scrollTop = Math.max(0, viewer.scrollTop - 200);
                } else if (e.wheelDeltaY < 0) {
                    viewer.scrollTop = viewer.scrollTop + 200;
                }
            } else {
                var y = (window.pageYOffset || document.documentElement.scrollTop || 0);
                if (e.wheelDeltaY > 0) {
                    window.scrollTo(0, Math.max(0, y - 200));
                } else if (e.wheelDeltaY < 0) {
                    window.scrollTo(0, y + 200);
                }
            }
        }, false);
    }

    // ---- Init ----

    function init() {
        bindEvents();
        updateStatus();
        pollTimer = setInterval(updateStatus, POLL_INTERVAL);

        document.addEventListener("touchmove", function(e) {
            e.preventDefault();
        }, false);
    }

    if (document.readyState === "complete" || document.readyState === "interactive") {
        init();
    } else {
        document.addEventListener("DOMContentLoaded", init, false);
    }

    return {
        refresh: updateStatus
    };

})();
