#!/usr/bin/env python3
"""Mock API server for BTManager WAF app UI testing.

Serves the WAF app static files and mocks all API endpoints with
realistic state transitions. Use with a browser or puppeteer to
test the UI without a Kindle.

Usage:
    python3 tests/mock_api_server.py
    # Open http://localhost:8321/index.html
"""
import json
import os
import urllib.parse
from http.server import HTTPServer, SimpleHTTPRequestHandler

WAF_DIR = os.path.join(os.path.dirname(__file__), "..", "illusion", "BTManager")
WAF_DIR = os.path.abspath(WAF_DIR)
PORT = 8321

# Mutable state for testing interactions
state = {
    "daemon_running": True,
    "scanning": False,
    "pairing": False,
    "devices": [
        {"address": "98:B9:EA:01:67:68", "protocol": "classic", "name": "Xbox Wireless Controller"},
        {"address": "5C:2B:3E:50:4F:04", "protocol": "ble", "name": "BLE-M3"},
    ],
    "connected_device": None,
    "connected_protocol": None,
    "connected_name": None,
    "version": "3.0.0",
    "scan_results": [
        {"address": "AA:BB:CC:DD:EE:01", "name": "BT Keyboard", "protocol": "classic", "rssi": -45},
        {"address": "AA:BB:CC:DD:EE:02", "name": "Page Turner", "protocol": "ble", "rssi": -62},
        {"address": "AA:BB:CC:DD:EE:03", "name": None, "protocol": "classic", "rssi": -78},
    ],
}


def _parse_param(path, key):
    """Extract and URL-decode a query parameter."""
    if f"{key}=" not in path:
        return None
    raw = path.split(f"{key}=")[-1].split("&")[0]
    return urllib.parse.unquote(raw)


class MockHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self._json({"ok": True})

        elif self.path == "/status":
            resp = {
                "ok": True,
                "daemon_running": state["daemon_running"],
                "device_count": len(state["devices"]),
                "devices": state["devices"],
                "version": state["version"],
                "scanning": state["scanning"],
                "pairing": state["pairing"],
            }
            if state["connected_device"]:
                resp["connected_device"] = state["connected_device"]
                resp["connected_protocol"] = state["connected_protocol"]
                resp["connected_name"] = state["connected_name"]
            self._json(resp)

        elif self.path == "/scan":
            state["scanning"] = True
            self._json({"ok": True, "message": "Scan started"})

        elif self.path == "/scan-status":
            self._json({
                "ok": True,
                "scanning": state["scanning"],
                "devices": state["scan_results"],
            })

        elif self.path == "/scan-stop":
            state["scanning"] = False
            self._json({"ok": True})

        elif self.path.startswith("/pair?"):
            state["pairing"] = True
            self._json({"ok": True, "message": "Pairing started"})

        elif self.path == "/pair-status":
            self._json({"ok": True, "pairing": state["pairing"], "stage": "waiting"})

        elif self.path == "/start":
            state["daemon_running"] = True
            self._json({"ok": True})

        elif self.path == "/stop":
            state["daemon_running"] = False
            state["connected_device"] = None
            self._json({"ok": True})

        elif self.path.startswith("/connect?"):
            addr = _parse_param(self.path, "addr")
            proto = _parse_param(self.path, "proto") or "classic"
            state["connected_device"] = addr
            state["connected_protocol"] = proto
            state["connected_name"] = None
            for d in state["devices"]:
                if d["address"].upper() == addr.upper():
                    state["connected_name"] = d.get("name")
            self._json({"ok": True})

        elif self.path.startswith("/disconnect"):
            state["connected_device"] = None
            state["connected_protocol"] = None
            state["connected_name"] = None
            self._json({"ok": True})

        elif self.path.startswith("/remove?"):
            addr = _parse_param(self.path, "addr")
            if addr:
                state["devices"] = [
                    d for d in state["devices"]
                    if d["address"].upper() != addr.upper()
                ]
            self._json({"ok": True})

        elif self.path.startswith("/add-device?"):
            addr = _parse_param(self.path, "addr")
            proto = _parse_param(self.path, "proto") or "classic"
            name = _parse_param(self.path, "name")
            if addr:
                state["devices"].append({
                    "address": addr,
                    "protocol": proto,
                    "name": name,
                })
            self._json({"ok": True})

        elif self.path == "/devices":
            self._json({"ok": True, "devices": state["devices"]})

        elif self.path == "/logs":
            self._json({"ok": True, "logs": [
                "2026-03-01 12:00:01 INFO daemon: HID Daemon v3.0.0",
                "2026-03-01 12:00:02 INFO ble_hid: API server listening on port 8321",
                "2026-03-01 12:00:03 INFO daemon: Waiting for connection...",
            ]})

        elif self.path == "/clear-cache":
            self._json({"ok": True, "message": "Cache cleared"})

        else:
            self.directory = WAF_DIR
            super().do_GET()

    def _json(self, data):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def translate_path(self, path):
        """Serve WAF files for non-API paths."""
        import posixpath
        path = urllib.parse.unquote(path.split("?")[0])
        path = posixpath.normpath(path)
        parts = [p for p in path.split("/") if p]
        result = WAF_DIR
        for p in parts:
            result = os.path.join(result, p)
        return result

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", PORT), MockHandler)
    print(f"Mock API server on http://localhost:{PORT}")
    print(f"Open http://localhost:{PORT}/index.html to test the WAF app")
    server.serve_forever()
