"""Local HTTP server for the Cloud IAM Risk Analyzer dashboard and demo API."""
from __future__ import annotations

import json
import threading
import webbrowser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from .scanner import scan_sample, scan_gcp_project
import os

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_ROOT = PROJECT_ROOT / "frontend"
BIND_HOST = "127.0.0.1"
# This Windows server binds IPv4 only. Use its literal address because Windows
# resolves "localhost" to IPv6 ::1 first on some machines.
DISPLAY_HOST = BIND_HOST
FIRST_PORT = 8004
LATEST_SCAN: dict | None = None


def empty_dashboard() -> dict:
    return {
        "timestamp": None,
        "identities": [],
        "findings": [],
        "metrics": {
            "identity_count": 0,
            "finding_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "risk_score": 0,
            "compliance": 0,
        },
    }


class AnalyzerHandler(SimpleHTTPRequestHandler):
    """Serve the frontend files and a small JSON API from one local server."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_ROOT), **kwargs)

    def log_message(self, message_format: str, *args) -> None:
        print(f"[{self.log_date_time_string()}] {message_format % args}")

    def send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = unquote(urlparse(self.path).path)
        if path == "/api/health":
            self.send_json(
                {
                    "ok": True,
                    "mode": "sample-demo",
                    "message": "Local demo API is running; no cloud account is connected.",
                }
            )
            return
        if path == "/api/dashboard":
            self.send_json(LATEST_SCAN or empty_dashboard())
            return
        if path == "/api/config":
            self.send_json({"mode": "gcp-read-only" if os.environ.get("GCP_PROJECT_ID") else "sample-demo", "project_id": os.environ.get("GCP_PROJECT_ID")})
            return
        super().do_GET()

    def do_POST(self) -> None:
        global LATEST_SCAN
        path = unquote(urlparse(self.path).path)
        if path == "/api/scan":
            project_id = os.environ.get("GCP_PROJECT_ID")
            try:
                LATEST_SCAN = scan_gcp_project(project_id) if project_id else scan_sample()
                self.send_json(LATEST_SCAN)
            except Exception as error:
                self.send_json({"error": str(error)}, status=502)
            return

        prefix = "/api/findings/"
        suffix = "/review"
        if path.startswith(prefix) and path.endswith(suffix):
            finding_id = path[len(prefix):-len(suffix)]
            if LATEST_SCAN is None:
                self.send_json({"error": "Run a sample scan first."}, status=409)
                return
            finding = next(
                (item for item in LATEST_SCAN["findings"] if item["id"] == finding_id),
                None,
            )
            if finding is None:
                self.send_json({"error": "Finding not found."}, status=404)
                return
            finding["status"] = "Reviewed"
            self.send_json({"finding": finding})
            return

        self.send_json({"error": "Endpoint not found."}, status=404)


class LocalHTTPServer(ThreadingHTTPServer):
    """Avoid sharing a port with stale server processes on Windows."""

    allow_reuse_address = False
    allow_reuse_port = False
    daemon_threads = True


def create_server() -> tuple[ThreadingHTTPServer, str]:
    for port in range(FIRST_PORT, FIRST_PORT + 20):
        try:
            server = LocalHTTPServer((BIND_HOST, port), AnalyzerHandler)
            return server, f"http://{DISPLAY_HOST}:{port}/"
        except OSError as error:
            if error.errno not in (48, 98, 10048):
                raise
    raise OSError("Ports 8004–8023 are busy. Stop an old analyzer server and try again.")


def main() -> None:
    server, dashboard_url = create_server()
    serving = threading.Thread(
        target=server.serve_forever,
        name="iam-http-server",
        daemon=True,
    )
    serving.start()
    print("Cloud IAM Risk Analyzer is ready.", flush=True)
    print(f"Open {dashboard_url} in your browser.", flush=True)
    print("Mode: synthetic sample data only; no cloud account is connected.", flush=True)

    def open_dashboard() -> None:
        try:
            webbrowser.open(dashboard_url)
        except Exception as error:
            print(f"Could not open a browser automatically: {error}", flush=True)

    browser_timer = threading.Timer(0.8, open_dashboard)
    browser_timer.daemon = True
    browser_timer.start()
    try:
        serving.join()
    except KeyboardInterrupt:
        server.shutdown()
        print("\nBackend stopped.")
    finally:
        browser_timer.cancel()
        server.server_close()


if __name__ == "__main__":
    main()
