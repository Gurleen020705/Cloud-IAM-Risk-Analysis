"""Vercel serverless API for the sample IAM dashboard."""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from backend.scanner import scan_gcp_project, scan_sample


def empty_dashboard() -> dict[str, Any]:
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


def request_path(request_target: str) -> str:
    parsed = urlparse(request_target)
    route = parse_qs(parsed.query).get("route", [parsed.path])[0]
    return unquote(route)


def get_response(path: str) -> tuple[dict[str, Any], int]:
    if path == "/api/health":
        return {
            "ok": True,
            "mode": "sample-demo",
            "message": "Demo API is running; no cloud account is connected.",
        }, 200
    if path == "/api/config":
        project_id = os.environ.get("GCP_PROJECT_ID")
        return {
            "mode": "gcp-read-only" if project_id else "sample-demo",
            "project_id": project_id,
        }, 200
    if path == "/api/dashboard":
        return empty_dashboard(), 200
    return {"error": "Endpoint not found."}, 404


def post_response(path: str) -> tuple[dict[str, Any], int]:
    if path == "/api/scan":
        project_id = os.environ.get("GCP_PROJECT_ID")
        try:
            result = scan_gcp_project(project_id) if project_id else scan_sample()
            return result, 200
        except Exception as error:
            return {"error": str(error)}, 502

    prefix = "/api/findings/"
    suffix = "/review"
    if path.startswith(prefix) and path.endswith(suffix):
        finding_id = path[len(prefix):-len(suffix)]
        if finding_id:
            return {
                "error": (
                    "Review status is not stored by Vercel functions. "
                    "The dashboard tracks review status in this browser session."
                )
            }, 409
    return {"error": "Endpoint not found."}, 404


class handler(BaseHTTPRequestHandler):
    """Vercel Python runtime handler for the dashboard API routes."""

    def send_json(self, payload: dict[str, Any], status: int) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = request_path(self.path)
        payload, status = get_response(path)
        self.send_json(payload, status)

    def do_POST(self) -> None:
        path = request_path(self.path)
        payload, status = post_response(path)
        self.send_json(payload, status)
