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

    var pollTimer = null;
    var messageTimer = null;
    var confirmAction = null;
    var confirmAddr = null;
    var lastStatus = null;
    var isScanning = false;
    var isPairing = false;
    var scanPollTimer = null;
    var pairPollTimer = null;
    var logPollTimer = null;
    var logsVisible = false;
    var pairLogTimer = null;

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
        bar.innerHTML = text;
        bar.className = "message-bar visible" + (isError ? " error" : "");
        if (messageTimer) clearTimeout(messageTimer);
        messageTimer = setTimeout(function() {
            bar.className = "message-bar";
        }, MESSAGE_TIMEOUT);
    }

    function setStatus(id, text, className) {
        var el = getEl(id);
        el.innerHTML = text;
        el.className = "status-value " + (className || "");
    }

    function escapeHtml(str) {
        if (!str) return "";
        return str.replace(/&/g, "&amp;")
                  .replace(/</g, "&lt;")
                  .replace(/>/g, "&gt;")
                  .replace(/"/g, "&quot;");
    }

    // ---- Status Polling ----

    function updateStatus() {
        request("/status", function(data, err) {
            if (err) {
                setStatus("statusDaemon", "unknown", "unknown");
                setStatus("statusDevices", "--", "unknown");
                renderDeviceList(null);
                return;
            }

            if (data.scanning) {
                setStatus("statusDaemon", "scanning...", "running");
            } else if (data.pairing) {
                setStatus("statusDaemon", "pairing...", "running");
            } else if (data.daemon_running) {
                setStatus("statusDaemon", "running", "running");
            } else {
                setStatus("statusDaemon", "stopped", "stopped");
            }

            var count = data.devices ? data.devices.length : 0;
            setStatus("statusDevices", count + " configured", "");

            renderDeviceList(data.devices, data.connected_device || null);

            if (data.version) {
                getEl("footer").innerHTML = "HID Passthrough v" + escapeHtml(data.version);
            }

            lastStatus = data;
        });
    }

    // ---- Device List ----

    function renderDeviceList(devices, connectedAddr) {
        var container = getEl("deviceList");

        if (!devices || devices.length === 0) {
            container.innerHTML = '<div class="device-empty">No devices configured</div>';
            return;
        }

        var html = "";
        for (var i = 0; i < devices.length; i++) {
            var dev = devices[i];
            var addr = escapeHtml(dev.address || "unknown");
            var proto = escapeHtml(dev.protocol || "");
            var name = escapeHtml(dev.name || "");
            var displayName = name || addr;
            var isConnected = connectedAddr && dev.address &&
                dev.address.toUpperCase() === connectedAddr.toUpperCase();

            html += '<div class="device-item' + (isConnected ? ' device-connected' : '') + '">';
            html += '<button class="device-remove" data-addr="' + escapeHtml(dev.address) + '">Remove</button>';
            if (isConnected) {
                html += '<button class="device-disconnect" data-addr="' + escapeHtml(dev.address) + '">Disconnect</button>';
            } else {
                html += '<button class="device-connect" data-addr="' + escapeHtml(dev.address) + '" data-proto="' + proto + '">Connect</button>';
            }
            html += '<div class="device-info">';
            html += '<div class="device-name">' + displayName;
            if (isConnected) {
                html += ' <span class="device-status-tag">Connected</span>';
            }
            html += '</div>';
            html += '<div>';
            html += '<span class="device-addr">' + addr + '</span>';
            if (proto) {
                html += '<span class="device-proto">[' + proto + ']</span>';
            }
            html += '</div>';
            html += '</div>';
            html += '</div>';
        }

        container.innerHTML = html;
    }

    // ---- Actions ----

    function startDaemon() {
        pressBtn("btnStart");
        showMessage("Starting daemon...", false);
        request("/start", function(data, err) {
            releaseBtn("btnStart");
            if (err) {
                showMessage("Error: " + err, true);
                return;
            }
            if (data && data.ok) {
                showMessage("Daemon started", false);
            } else {
                showMessage(data && data.error ? data.error : "Failed to start", true);
            }
            setTimeout(updateStatus, 1500);
        });
    }

    function stopDaemon() {
        pressBtn("btnStop");
        showMessage("Stopping daemon...", false);
        request("/stop", function(data, err) {
            releaseBtn("btnStop");
            if (err) {
                showMessage("Error: " + err, true);
                return;
            }
            if (data && data.ok) {
                showMessage("Daemon stopped", false);
            } else {
                showMessage(data && data.error ? data.error : "Failed to stop", true);
            }
            setTimeout(updateStatus, 1000);
        });
    }

    function connectDevice(addr, protocol) {
        showMessage("Connecting to " + addr + "...", false);
        var url = "/connect?addr=" + encodeURIComponent(addr);
        if (protocol) url += "&protocol=" + encodeURIComponent(protocol);
        request(url, function(data, err) {
            if (err) {
                showMessage("Error: " + err, true);
                return;
            }
            if (data && data.ok) {
                showMessage("Connecting...", false);
            } else {
                showMessage(data && data.error ? data.error : "Failed to connect", true);
            }
            setTimeout(updateStatus, 2000);
        });
    }

    function disconnectDevice(addr) {
        showMessage("Disconnecting " + addr + "...", false);
        request("/disconnect?addr=" + encodeURIComponent(addr), function(data, err) {
            if (err) {
                showMessage("Error: " + err, true);
                return;
            }
            if (data && data.ok) {
                showMessage("Disconnected", false);
            } else {
                showMessage(data && data.error ? data.error : "Failed to disconnect", true);
            }
            setTimeout(updateStatus, 1000);
        });
    }

    function removeDevice(addr) {
        showMessage("Removing " + addr + "...", false);
        request("/remove?addr=" + encodeURIComponent(addr), function(data, err) {
            releaseBtn("dialogConfirmBtn");
            if (err) {
                showMessage("Error: " + err, true);
                return;
            }
            if (data && data.ok) {
                showMessage("Device removed: " + addr, false);
            } else {
                showMessage(data && data.error ? data.error : "Failed to remove", true);
            }
            setTimeout(updateStatus, 500);
        });
    }

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
                showMessage(data && data.error ? data.error : "Failed to clear cache", true);
            }
        });
    }

    // ---- Quit ----

    function quit() {
        pressBtn("btnBack");
        if (typeof kindle !== "undefined" && kindle.appmgr && kindle.appmgr.back) {
            kindle.appmgr.back();
        }
    }

    // ---- Scan & Pair ----

    function startScan() {
        if (isScanning || isPairing) return;
        isScanning = true;

        var btn = getEl("btnScan");
        pressBtn(btn);
        btn.innerHTML = "Scanning...";
        btn.disabled = true;

        var statusEl = getEl("scanStatus");
        statusEl.innerHTML = "Scanning for BLE &amp; Classic HID devices...";
        statusEl.style.display = "block";
        getEl("scanResults").innerHTML = "";

        request("/scan", function(data, err) {
            if (err) {
                showMessage("Scan error: " + err, true);
                resetScanUI();
                return;
            }
            // Start polling for results
            pollScanStatus();
        });
    }

    function pollScanStatus() {
        scanPollTimer = setTimeout(function() {
            request("/scan-status", function(data, err) {
                if (err) {
                    showMessage("Scan poll error: " + err, true);
                    resetScanUI();
                    return;
                }
                if (data && data.scanning) {
                    // Still scanning - show results found so far
                    if (data.devices && data.devices.length > 0) {
                        renderScanResults(data.devices);
                    }
                    pollScanStatus();
                    return;
                }
                // Scan complete
                resetScanUI();
                if (data && data.ok && data.devices) {
                    renderScanResults(data.devices);
                    if (data.devices.length === 0) {
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
        releaseBtn(btn);
        btn.innerHTML = "Scan for Devices";
        btn.disabled = false;
        getEl("scanStatus").style.display = "none";
        if (scanPollTimer) {
            clearTimeout(scanPollTimer);
            scanPollTimer = null;
        }
    }

    function renderScanResults(devices) {
        var container = getEl("scanResults");
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
            var rssi = dev.rssi !== undefined ? dev.rssi : "";

            html += '<div class="scan-device-item">';
            html += '<button class="btn-pair" data-addr="' + addr + '" data-proto="' + proto + '" data-name="' + name + '">';
            html += 'Pair</button>';
            html += '<div class="scan-device-info">';
            html += '<div class="scan-device-name">' + name + '</div>';
            html += '<div>';
            html += '<span class="scan-device-meta">' + addr + ' [' + proto + ']</span>';
            if (rssi !== "") {
                html += '<span class="scan-device-rssi">RSSI: ' + rssi + '</span>';
            }
            html += '</div>';
            html += '</div>';
            html += '</div>';
        }

        container.innerHTML = html;
    }

    function startPair(addr, protocol, name) {
        if (isPairing) return;
        if (isScanning) {
            // Stop scan before pairing
            request("/scan-stop", function() {});
            resetScanUI();
        }
        isPairing = true;

        // Show overlay with live logs (scroll to top so header/X visible)
        window.scrollTo(0, 0);
        getEl("pairMessage").innerHTML = "Pairing...";
        getEl("pairAddr").innerHTML = escapeHtml(addr);
        getEl("pairLogContent").innerHTML = "";
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
                    showMessage("Pair poll error: " + err, true);
                    resetPairUI();
                    return;
                }
                if (data && data.pairing) {
                    // Still pairing, update message and poll again
                    getEl("pairMessage").innerHTML = "Pairing in progress...";
                    pollPairStatus();
                    return;
                }
                // Pairing complete
                resetPairUI();
                if (data && data.ok) {
                    showMessage("Paired: " + (data.address || ""), false);
                    getEl("scanResults").innerHTML = "";
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
                viewer.innerHTML = escapeHtml(data.lines.join("\n"));
                var container = viewer.parentNode;
                container.scrollTop = container.scrollHeight;
            }
            if (isPairing) {
                pairLogTimer = setTimeout(pollPairLogs, 2000);
            }
        });
    }

    // ---- Log Viewer (fullscreen overlay) ----

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
                getEl("logContent").innerHTML = "Error loading logs: " + escapeHtml(err);
                return;
            }
            if (data && data.lines) {
                getEl("logContent").innerHTML = escapeHtml(data.lines.join("\n"));
                var viewer = getEl("logViewer");
                viewer.scrollTop = viewer.scrollHeight;
            }
            if (logsVisible) {
                logPollTimer = setTimeout(fetchLogs, 3000);
            }
        });
    }

    // ---- Confirm Dialog ----

    function showConfirm(message, action) {
        getEl("dialogMessage").innerHTML = message;
        getEl("confirmOverlay").className = "overlay visible";
        confirmAction = action;
    }

    function confirmRemoveDevice(addr) {
        confirmAddr = addr;
        showConfirm(
            "Remove device?<br/><span class=\"dialog-addr\">" + escapeHtml(addr) + "</span>",
            "remove"
        );
    }

    function confirmClearCache() {
        showConfirm("Clear all cached HID descriptors?", "cache");
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
        bindBtn("btnBack", quit);
        bindBtn("btnStart", startDaemon);
        bindBtn("btnStop", stopDaemon);
        bindBtn("btnScan", startScan);
        bindBtn("btnPairClose", cancelPair);
        bindBtn("btnLogs", showLogs);
        bindBtn("btnLogClose", hideLogs);
        bindBtn("btnLogUp", scrollLogsUp);
        bindBtn("btnLogDown", scrollLogsDown);
        bindBtn("btnClearCache", confirmClearCache);

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

        // Event delegation for dynamically created buttons
        document.addEventListener("click", function(e) {
            var target = e.target;
            if (!target) return;
            var addr, proto;
            if (target.className && target.className.indexOf("device-disconnect") !== -1) {
                addr = target.getAttribute("data-addr");
                if (addr) disconnectDevice(addr);
            } else if (target.className && target.className.indexOf("device-connect") !== -1) {
                addr = target.getAttribute("data-addr");
                proto = target.getAttribute("data-proto");
                if (addr) connectDevice(addr, proto || "ble");
            } else if (target.className && target.className.indexOf("device-remove") !== -1) {
                addr = target.getAttribute("data-addr");
                if (addr) confirmRemoveDevice(addr);
            } else if (target.className && target.className.indexOf("btn-pair") !== -1) {
                addr = target.getAttribute("data-addr");
                proto = target.getAttribute("data-proto");
                var name = target.getAttribute("data-name");
                if (addr) startPair(addr, proto || "ble", name || "");
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

        // Block all page scrolling globally — Kindle WebKit 533 doesn't
        // support position:fixed, so we prevent body scroll entirely.
        // The log viewer scrolls internally via its own scroll buttons.
        document.addEventListener("touchmove", function(e) {
            e.preventDefault();
        }, false);
    }

    // Start when DOM is ready
    if (document.readyState === "complete" || document.readyState === "interactive") {
        init();
    } else {
        document.addEventListener("DOMContentLoaded", init, false);
    }

    // Public API (for debugging)
    return {
        refresh: updateStatus
    };

})();
