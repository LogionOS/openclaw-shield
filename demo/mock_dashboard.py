#!/usr/bin/env python3
"""
Mock server for LogionOS Shield Dashboard demo.
Serves the dashboard HTML + provides mock API endpoints.

Run: python3 demo/mock_dashboard.py
Then open: http://localhost:18789/logionos/
"""

import http.server
import json
import os
import time
import random

PORT = 18789
START_TIME = time.time()

DASHBOARD_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "dashboard", "dashboard.html"
)

MOCK_STATUS = {
    "shield": {
        "mode": "enforce",
        "uptime": 0,
        "guards": {
            "inbound": True,
            "outbound": True,
            "prompt": True,
            "tool": True
        }
    },
    "compliance": {
        "total": 1847,
        "passed": 1623,
        "warned": 89,
        "flagged": 67,
        "blocked": 68
    },
    "policy": {
        "healthy": True,
        "lastSync": "2026-03-09T09:30:00Z",
        "ruleCount": 4004
    }
}

MOCK_SESSIONS = {
    "sessions": [
        {
            "channelId": "slack-#ai-ops",
            "userId": "eng-team-lead",
            "startedAt": "2026-03-09T08:15:00Z",
            "messageCount": 34,
            "complianceEvents": 3,
            "lastActivity": "2026-03-09T10:02:00Z"
        },
        {
            "channelId": "teams-compliance",
            "userId": "compliance-officer",
            "startedAt": "2026-03-09T09:00:00Z",
            "messageCount": 12,
            "complianceEvents": 0,
            "lastActivity": "2026-03-09T09:45:00Z"
        },
        {
            "channelId": "discord-dev",
            "userId": "dev-intern",
            "startedAt": "2026-03-09T09:30:00Z",
            "messageCount": 67,
            "complianceEvents": 8,
            "lastActivity": "2026-03-09T10:05:00Z"
        }
    ]
}


class DemoHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")

    def _json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self._cors()
        self.end_headers()
        self.write_safe(body)

    def _html(self, content):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self._cors()
        self.end_headers()
        self.write_safe(content.encode("utf-8"))

    def write_safe(self, data):
        try:
            self.wfile.write(data)
        except BrokenPipeError:
            pass

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]

        if path in ("/logionos/", "/logionos"):
            with open(DASHBOARD_PATH, "r", encoding="utf-8") as f:
                html = f.read()
            self._html(html)

        elif path == "/logionos/status":
            status = MOCK_STATUS.copy()
            status["shield"] = dict(MOCK_STATUS["shield"])
            status["shield"]["uptime"] = int(time.time() - START_TIME)
            c = status["compliance"]
            c["total"] += random.randint(0, 3)
            c["passed"] += random.randint(0, 2)
            if random.random() < 0.3:
                c["warned"] += 1
            if random.random() < 0.15:
                c["flagged"] += 1
            if random.random() < 0.1:
                c["blocked"] += 1
            self._json(status)

        elif path == "/logionos/sessions":
            self._json(MOCK_SESSIONS)

        elif path == "/logionos/stats":
            self._json({
                "rules": 4004,
                "jurisdictions": 6,
                "avgLatencyMs": round(random.uniform(12, 45), 1),
                "p99LatencyMs": round(random.uniform(80, 180), 1),
            })

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/logionos/kill-switch":
            self._json({"status": "activated", "timestamp": time.time()})
        elif path.startswith("/logionos/mode/"):
            mode = path.split("/")[-1]
            MOCK_STATUS["shield"]["mode"] = mode
            self._json({"mode": mode})
        else:
            self._json({"error": "not found"}, 404)


def main():
    print(f"\033[96m\033[1m")
    print(f"  LogionOS Shield — Dashboard Demo Server")
    print(f"\033[0m")
    print(f"  Dashboard: \033[4mhttp://localhost:{PORT}/logionos/\033[0m")
    print(f"  Status API: http://localhost:{PORT}/logionos/status")
    print(f"  Press Ctrl+C to stop\n")

    server = http.server.HTTPServer(("", PORT), DemoHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
