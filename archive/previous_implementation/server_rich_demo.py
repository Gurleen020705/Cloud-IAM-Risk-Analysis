"""Local demo API and explainable IAM risk scanner (Python standard library only)."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse
import webbrowser

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "iam_analyzer.sqlite3"
HOST, PORT = "127.0.0.1", 8000
DB_LOCK = threading.RLock()
JOBS: dict[str, dict] = {}
JOB_LOCK = threading.RLock()

# Synthetic records only. Provider adapters should replace this fixture after
# implementing read-only, least-privilege authentication and provider pagination.
IDENTITIES = [
    {"id": "u-1001", "name": "Alex Morgan", "email": "alex.morgan@acme.demo", "type": "Human", "mfa": False, "admin": True, "permissions": ["*"], "key_age_days": 0, "inactive_days": 2, "owner": "Platform Security"},
    {"id": "s-2001", "name": "svc-deploy-prod", "email": "service · Production", "type": "Service account", "mfa": None, "admin": False, "permissions": ["compute:*", "iam:PassRole"], "key_age_days": 241, "inactive_days": 0, "owner": "Platform Engineering"},
    {"id": "u-1002", "name": "Taylor Kim", "email": "taylor.kim@acme.demo", "type": "Human", "mfa": True, "admin": False, "permissions": ["storage:*", "database:read"], "key_age_days": 0, "inactive_days": 1, "owner": "Data Platform"},
    {"id": "s-2002", "name": "svc-legacy-api", "email": "service · Legacy API", "type": "Service account", "mfa": None, "admin": True, "permissions": ["*"], "key_age_days": 195, "inactive_days": 96, "owner": "Application Team"},
    {"id": "u-1003", "name": "Morgan Lee", "email": "morgan.lee@acme.demo", "type": "Human", "mfa": True, "admin": False, "permissions": ["storage:read"], "key_age_days": 198, "inactive_days": 3, "owner": "Data Platform"},
    {"id": "s-2003", "name": "svc-data-pipeline", "email": "service · Analytics", "type": "Service account", "mfa": None, "admin": False, "permissions": ["database:*", "storage:write"], "key_age_days": 183, "inactive_days": 0, "owner": "Analytics"},
    {"id": "u-1004", "name": "Jamie Patel", "email": "jamie.patel@acme.demo", "type": "Human", "mfa": False, "admin": False, "permissions": ["compute:read"], "key_age_days": 0, "inactive_days": 1, "owner": "Engineering"},
    {"id": "u-1005", "name": "Chris Wong", "email": "chris.wong@acme.demo", "type": "Human", "mfa": True, "admin": True, "permissions": ["iam:policy:write"], "key_age_days": 0, "inactive_days": 102, "owner": "Platform Security"},
    {"id": "s-2004", "name": "svc-backup-east", "email": "service · Backup", "type": "Service account", "mfa": None, "admin": False, "permissions": ["storage:*"], "key_age_days": 72, "inactive_days": 0, "owner": "Infrastructure"},
    {"id": "u-1006", "name": "Riley Chen", "email": "riley.chen@acme.demo", "type": "Human", "mfa": True, "admin": False, "permissions": ["storage:read"], "key_age_days": 126, "inactive_days": 0, "owner": "Engineering"},
    {"id": "u-1007", "name": "Drew Rivera", "email": "drew.rivera@acme.demo", "type": "Human", "mfa": False, "admin": False, "permissions": ["compute:read"], "key_age_days": 0, "inactive_days": 2, "owner": "Engineering"},
    {"id": "s-2005", "name": "svc-monitoring", "email": "service · Observability", "type": "Service account", "mfa": None, "admin": False, "permissions": ["logs:read", "metrics:read"], "key_age_days": 40, "inactive_days": 0, "owner": "SRE"},
]

RULES = {
    "IAM-001": {"title": "Privileged identity without MFA", "severity": "Critical", "points": 45, "recommendation": "Enable MFA, verify a break-glass path, then review all admin grants."},
    "IAM-002": {"title": "Wildcard or broad permissions", "severity": "High", "points": 28, "recommendation": "Replace wildcard actions with the smallest resource-scoped permissions needed."},
    "IAM-003": {"title": "Stale access key", "severity": "High", "points": 20, "recommendation": "Rotate the key, validate dependent workloads, and revoke the old key."},
    "IAM-004": {"title": "Inactive privileged identity", "severity": "High", "points": 25, "recommendation": "Confirm ownership and business need; disable the identity or remove privileged grants."},
    "IAM-005": {"title": "Human identity without MFA", "severity": "Medium", "points": 15, "recommendation": "Require MFA through the organization identity provider."},
    "IAM-006": {"title": "Access key approaching rotation limit", "severity": "Medium", "points": 10, "recommendation": "Rotate the key before it reaches the 180-day review threshold."},
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def evaluate(identity: dict) -> list[dict]:
    """Return evidence-backed findings; this demo evaluates local fixture records."""
    found = []
    permissions = identity["permissions"]
    broad = identity["admin"] or any("*" in permission for permission in permissions)
    checks = [
        (identity["admin"] and identity["type"] == "Human" and identity["mfa"] is False, "IAM-001", "Privileged access is enabled while MFA is disabled."),
        (any(permission == "*" or permission.endswith(":*") for permission in permissions), "IAM-002", f"Effective permissions include broad grant(s): {', '.join(permissions)}."),
        (identity["key_age_days"] > 180, "IAM-003", f"Credential age is {identity['key_age_days']} days; policy threshold is 180 days."),
        (identity["inactive_days"] > 90 and broad, "IAM-004", f"Identity has been inactive for {identity['inactive_days']} days and retains broad access."),
        (identity["type"] == "Human" and identity["mfa"] is False and not identity["admin"], "IAM-005", "MFA is not enabled for this human identity."),
        (90 < identity["key_age_days"] <= 180, "IAM-006", f"Credential age is {identity['key_age_days']} days; rotate before day 180."),
    ]
    for matches, rule_id, evidence in checks:
        if matches:
            rule = RULES[rule_id]
            found.append({"rule_id": rule_id, "title": rule["title"], "severity": rule["severity"], "points": rule["points"], "evidence": evidence, "recommendation": rule["recommendation"]})
    return found


def assessed_inventory() -> list[dict]:
    result = []
    for identity in IDENTITIES:
        findings = evaluate(identity)
        score = min(100, sum(item["points"] for item in findings))
        level = "Critical" if score >= 70 else "High" if score >= 40 else "Medium" if score >= 15 else "Low"
        result.append({**identity, "findings": findings, "score": score, "level": level})
    return result


def db_connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=8)
    connection.row_factory = sqlite3.Row
    return connection


@contextmanager
def database():
    with DB_LOCK:
        connection = db_connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def initialize_db() -> None:
    with database() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY, started_at TEXT NOT NULL, completed_at TEXT,
            status TEXT NOT NULL, total_identities INTEGER NOT NULL DEFAULT 0,
            overall_score INTEGER NOT NULL DEFAULT 0, critical_count INTEGER NOT NULL DEFAULT 0,
            high_count INTEGER NOT NULL DEFAULT 0, medium_count INTEGER NOT NULL DEFAULT 0,
            compliance_percent INTEGER NOT NULL DEFAULT 0,
            source TEXT NOT NULL DEFAULT 'demo', project_id TEXT, compliance_json TEXT
        );
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, identity_id TEXT NOT NULL,
            identity_name TEXT NOT NULL, identity_type TEXT NOT NULL, owner TEXT NOT NULL,
            rule_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
            evidence TEXT NOT NULL, recommendation TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open', created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
        CREATE TABLE IF NOT EXISTS identity_snapshots (
            scan_id TEXT NOT NULL, identity_id TEXT NOT NULL, payload_json TEXT NOT NULL,
            PRIMARY KEY(scan_id, identity_id)
        );
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS remediation_plans (
            id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, finding_id TEXT NOT NULL,
            project_id TEXT NOT NULL, rule_id TEXT NOT NULL, summary TEXT NOT NULL,
            impact TEXT NOT NULL, target_json TEXT NOT NULL, status TEXT NOT NULL,
            created_at TEXT NOT NULL, applied_at TEXT, result_json TEXT
        );
        """)
        scan_columns = {row[1] for row in db.execute("PRAGMA table_info(scans)").fetchall()}
        if "source" not in scan_columns:
            db.execute("ALTER TABLE scans ADD COLUMN source TEXT NOT NULL DEFAULT 'demo'")
        if "project_id" not in scan_columns:
            db.execute("ALTER TABLE scans ADD COLUMN project_id TEXT")
        if "compliance_json" not in scan_columns:
            db.execute("ALTER TABLE scans ADD COLUMN compliance_json TEXT")
        if db.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0:
            inventory = assessed_inventory()
            all_findings = [(identity, finding) for identity in inventory for finding in identity["findings"]]
            compliance = compute_compliance()
            db.execute("INSERT INTO scans(id,started_at,completed_at,status,total_identities,overall_score,critical_count,high_count,medium_count,compliance_percent) VALUES(?,?,?,?,?,?,?,?,?,?)",
                       ("baseline", utc_now(), utc_now(), "completed", len(IDENTITIES), round(sum(item["score"] for item in inventory) / len(inventory)), sum(finding["severity"] == "Critical" for _, finding in all_findings), sum(finding["severity"] == "High" for _, finding in all_findings), sum(finding["severity"] == "Medium" for _, finding in all_findings), compliance["percent"]))
            for identity in inventory:
                for finding in identity["findings"]:
                    fid = f"baseline:{identity['id']}:{finding['rule_id']}"
                    db.execute("INSERT OR IGNORE INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                               (fid, "baseline", identity["id"], identity["name"], identity["type"], identity["owner"], finding["rule_id"], finding["title"], finding["severity"], finding["evidence"], finding["recommendation"], "Open", utc_now()))


def latest_scan(db: sqlite3.Connection, source: str = "demo"):
    if source == "google_cloud":
        project_id = configured_gcp_project(db)
        if not project_id:
            return None
        return db.execute("SELECT * FROM scans WHERE status='completed' AND source=? AND project_id=? ORDER BY completed_at DESC LIMIT 1", (source, project_id)).fetchone()
    return db.execute("SELECT * FROM scans WHERE status='completed' AND source=? ORDER BY completed_at DESC LIMIT 1", (source,)).fetchone()


def configured_gcp_project(db: sqlite3.Connection | None = None) -> str:
    project = os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip()
    if project:
        return project
    if db is not None:
        row = db.execute("SELECT value FROM settings WHERE key='google_cloud_project_id'").fetchone()
        if row:
            return row[0]
    with database() as connection:
        row = connection.execute("SELECT value FROM settings WHERE key='google_cloud_project_id'").fetchone()
        return row[0] if row else ""


def compute_compliance() -> dict:
    humans = [item for item in IDENTITIES if item["type"] == "Human"]
    mfa_rate = round(100 * sum(item["mfa"] is True for item in humans) / len(humans))
    key_review = round(100 * sum(item["key_age_days"] <= 180 for item in IDENTITIES) / len(IDENTITIES))
    least_privilege = round(100 * sum(not any("*" in permission for permission in item["permissions"]) and not item["admin"] for item in IDENTITIES) / len(IDENTITIES))
    dormant = round(100 * sum(not (item["inactive_days"] > 90 and (item["admin"] or any("*" in permission for permission in item["permissions"]))) for item in IDENTITIES) / len(IDENTITIES))
    controls = [
        {"id": "mfa", "name": "MFA coverage", "percent": mfa_rate, "framework": "CIS 6.3", "status": "Compliant" if mfa_rate >= 90 else "Attention"},
        {"id": "least-privilege", "name": "Least privilege", "percent": least_privilege, "framework": "NIST AC-6", "status": "Compliant" if least_privilege >= 90 else "Attention"},
        {"id": "key-rotation", "name": "Credential rotation", "percent": key_review, "framework": "CIS 1.4", "status": "Compliant" if key_review >= 90 else "Attention"},
        {"id": "dormant", "name": "Dormant privileged access", "percent": dormant, "framework": "NIST AC-2", "status": "Compliant" if dormant >= 90 else "Attention"},
    ]
    return {"percent": round(sum(control["percent"] for control in controls) / len(controls)), "controls": controls}


def scan_worker(scan_id: str) -> None:
    try:
        with JOB_LOCK:
            job = JOBS[scan_id]
            job["status"] = "running"
            source = job["source"]
            project_id = job.get("project_id")

        if source == "google_cloud":
            from gcp_provider import GoogleCloudReader
            def report_progress(progress, phase):
                with JOB_LOCK:
                    JOBS[scan_id].update({"progress": progress, "phase": phase})
            result = GoogleCloudReader(project_id).scan(progress=report_progress)
            inventory = result["identities"]
            compliance = result["compliance"]
            caveats = result["caveats"]
        else:
            phases = [(18, "Inventorying demo identities"), (46, "Evaluating effective permissions"), (73, "Checking MFA and credential age"), (91, "Mapping findings to control checks")]
            for progress, phase in phases:
                time.sleep(0.7)
                with JOB_LOCK:
                    JOBS[scan_id].update({"progress": progress, "phase": phase})
            inventory = assessed_inventory()
            compliance = compute_compliance()
            caveats = ["Synthetic demo identities only; no Google Cloud project was queried."]

        all_findings = []
        for identity in inventory:
            for index, item in enumerate(identity["findings"]):
                item.update({"id": f"{scan_id}:{identity['id']}:{item['rule_id']}:{index}", "scan_id": scan_id, "identity_id": identity["id"], "identity_name": identity["name"], "identity_type": identity["type"], "owner": identity["owner"], "status": "Open"})
                all_findings.append((identity, item))
        critical = sum(item["severity"] == "Critical" for _, item in all_findings)
        high = sum(item["severity"] == "High" for _, item in all_findings)
        medium = sum(item["severity"] == "Medium" for _, item in all_findings)
        score = round(sum(item["score"] for item in inventory) / max(1, len(inventory)))
        completed_at = utc_now()
        with database() as db:
            db.execute("INSERT INTO scans(id,started_at,completed_at,status,total_identities,overall_score,critical_count,high_count,medium_count,compliance_percent,source,project_id,compliance_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (scan_id, JOBS[scan_id]["started_at"], completed_at, "completed", len(inventory), score, critical, high, medium, compliance["percent"], source, project_id, json.dumps(compliance)))
            for identity in inventory:
                db.execute("INSERT INTO identity_snapshots(scan_id,identity_id,payload_json) VALUES(?,?,?)",
                           (scan_id, str(identity["id"]), json.dumps(identity, ensure_ascii=False)))
            for identity, item in all_findings:
                item["created_at"] = completed_at
                db.execute("INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (item["id"], scan_id, str(identity["id"]), identity["name"], identity["type"], identity["owner"], item["rule_id"], item["title"], item["severity"], item["evidence"], item["recommendation"], "Open", completed_at))
        with JOB_LOCK:
            JOBS[scan_id].update({"status": "completed", "progress": 100, "phase": "Scan complete", "completed_at": completed_at, "summary": {"total_identities": len(inventory), "findings": len(all_findings), "critical": critical, "high": high, "medium": medium, "overall_score": score, "compliance_percent": compliance["percent"]}, "caveats": caveats})
    except Exception as exc:  # Keep failure visible to the UI without leaking request data.
        with JOB_LOCK:
            JOBS[scan_id].update({"status": "failed", "phase": "Scan failed", "error": str(exc)[:180]})


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, fmt, *args):
        print(f"[http] {self.address_string()} {fmt % args}")

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store" if self.path.startswith("/api/") else "no-cache")
        super().end_headers()

    def send_json(self, payload: dict, status: int = 200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 4096:
            raise ValueError("Request body too large")
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        query = parse_qs(parsed.query)
        if path == "/api/health":
            with database() as db:
                configured = configured_gcp_project(db)
                cloud_scan = latest_scan(db, "google_cloud")
            return self.send_json({"status": "ok", "service": "Cloud IAM Risk Analyzer API", "data_source": "google-cloud" if cloud_scan else "synthetic-demo-inventory", "cloud_connected": bool(cloud_scan), "project_configured": bool(configured), "timestamp": utc_now()})
        if path == "/api/cloud/status":
            from gcp_provider import adc_credentials_present
            with database() as db:
                project_id = configured_gcp_project(db)
                last_gcp_scan = latest_scan(db, "google_cloud")
            return self.send_json({"provider": "Google Cloud", "project_id": project_id, "project_configured": bool(project_id), "credentials_detected": adc_credentials_present(), "connected": bool(last_gcp_scan), "last_scan_at": last_gcp_scan["completed_at"] if last_gcp_scan else None, "scan_scope": "Single configured project; direct project allow-policy and service-account key metadata"})
        if path.startswith("/api/remediation/"):
            plan_id = path.removeprefix("/api/remediation/")
            with database() as db:
                row = db.execute("SELECT * FROM remediation_plans WHERE id=?", (plan_id,)).fetchone()
            if not row:
                return self.send_json({"error": "Remediation plan not found"}, 404)
            item = dict(row)
            item["target"] = json.loads(item.pop("target_json"))
            result_json = item.pop("result_json")
            item["result"] = json.loads(result_json) if result_json else None
            return self.send_json(item)
        if path == "/api/overview":
            source = query.get("source", ["demo"])[0]
            with database() as db:
                scan = latest_scan(db, source)
                row = dict(scan) if scan else {}
                if scan and scan["compliance_json"]:
                    row["compliance"] = json.loads(scan["compliance_json"])
                elif source == "google_cloud":
                    row["compliance"] = {"percent": 0, "controls": []}
                else:
                    row["compliance"] = compute_compliance()
                row["data_source"] = "Google Cloud project scan" if source == "google_cloud" and scan else "Synthetic sample inventory"
                row["cloud_connected"] = bool(source == "google_cloud" and scan)
                row["source"] = source
                row["identity_count"] = scan["total_identities"] if scan else (len(IDENTITIES) if source == "demo" else 0)
                if scan:
                    row["caveats"] = []
                return self.send_json(row)
        if path == "/api/identities":
            source = query.get("source", ["demo"])[0]
            q = query.get("q", [""])[0].lower()
            risk = query.get("risk", ["all"])[0]
            kind = query.get("type", ["all"])[0]
            if source == "google_cloud":
                with database() as db:
                    scan = latest_scan(db, source)
                    items = [json.loads(row[0]) for row in db.execute("SELECT payload_json FROM identity_snapshots WHERE scan_id=?", (scan["id"],)).fetchall()] if scan else []
            else:
                items = assessed_inventory()
            if q:
                items = [item for item in items if q in item["name"].lower() or q in item["email"].lower() or q in item["owner"].lower()]
            if risk.lower() != "all":
                items = [item for item in items if item["level"].lower() == risk.lower()]
            if kind.lower() != "all":
                items = [item for item in items if item["type"].lower() == kind.lower()]
            safe = [{key: item[key] for key in ("id", "name", "email", "type", "owner", "score", "level", "findings", "inactive_days", "key_age_days")} for item in items]
            return self.send_json({"items": safe, "total": len(safe)})
        if path == "/api/findings":
            source = query.get("source", ["demo"])[0]
            status_filter = query.get("status", ["all"])[0]
            severity_filter = query.get("severity", ["all"])[0]
            with database() as db:
                scan = latest_scan(db, source)
                if not scan:
                    return self.send_json({"items": [], "total": 0})
                sql = "SELECT * FROM findings WHERE scan_id=?"
                args = [scan["id"]]
                if status_filter.lower() != "all":
                    sql += " AND lower(status)=?"; args.append(status_filter.lower())
                if severity_filter.lower() != "all":
                    sql += " AND lower(severity)=?"; args.append(severity_filter.lower())
                sql += " ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 ELSE 3 END, created_at DESC"
                items = [dict(row) for row in db.execute(sql, args).fetchall()]
                return self.send_json({"items": items, "total": len(items), "scan_id": scan["id"]})
        if path == "/api/history":
            source = query.get("source", ["demo"])[0]
            with database() as db:
                if source == "google_cloud":
                    project_id = configured_gcp_project(db)
                    scans = [dict(row) for row in db.execute("SELECT id,completed_at,overall_score,compliance_percent,critical_count,high_count,source,project_id FROM scans WHERE status='completed' AND source=? AND project_id=? ORDER BY completed_at DESC LIMIT 12", (source, project_id)).fetchall()] if project_id else []
                else:
                    scans = [dict(row) for row in db.execute("SELECT id,completed_at,overall_score,compliance_percent,critical_count,high_count,source,project_id FROM scans WHERE status='completed' AND source=? ORDER BY completed_at DESC LIMIT 12", (source,)).fetchall()]
            return self.send_json({"items": list(reversed(scans))})
        if path.startswith("/api/scans/"):
            scan_id = path.removeprefix("/api/scans/")
            with JOB_LOCK:
                job = JOBS.get(scan_id)
                if job:
                    return self.send_json(job)
            with database() as db:
                row = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
                if row:
                    item = dict(row); item.update({"progress": 100, "phase": "Scan complete"})
                    return self.send_json(item)
            return self.send_json({"error": "Scan not found"}, 404)
        return super().do_GET()

    def do_POST(self):
        path = unquote(urlparse(self.path).path)
        origin = self.headers.get("Origin")
        if origin:
            from urllib.parse import urlparse as parse_url
            origin_host = parse_url(origin).netloc
            if origin_host not in ("127.0.0.1:8000", "localhost:8000"):
                return self.send_json({"error": "Cross-origin requests are not allowed."}, 403)
        if path == "/api/remediation/preview":
            try:
                payload = self.read_json()
            except (ValueError, json.JSONDecodeError) as exc:
                return self.send_json({"error": str(exc)}, 400)
            finding_id = str(payload.get("finding_id", ""))
            supported = {"GCP-001", "GCP-002", "GCP-003", "GCP-004", "GCP-006"}
            with database() as db:
                scan = latest_scan(db, "google_cloud")
                finding = db.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
                if not scan or not finding or finding["scan_id"] != scan["id"] or scan["source"] != "google_cloud":
                    return self.send_json({"error": "Finding is not from the latest Google Cloud scan. Run a fresh scan."}, 409)
                snapshot = db.execute("SELECT payload_json FROM identity_snapshots WHERE scan_id=? AND identity_id=?", (scan["id"], finding["identity_id"])).fetchone()
                if not snapshot:
                    return self.send_json({"error": "Finding evidence snapshot is unavailable."}, 409)
                identity = json.loads(snapshot[0])
                actual = next((entry for entry in identity.get("findings", []) if entry.get("rule_id") == finding["rule_id"]), None)
                if finding["rule_id"] not in supported or not actual or not actual.get("target"):
                    return self.send_json({"error": "This finding needs manual remediation review and cannot be safely changed by this prototype."}, 400)
                target = actual["target"]
                if finding["rule_id"] == "GCP-006":
                    summary = f"Disable user-managed key for {target['service_account']}"
                    impact = "Disabling this key may break workloads that still use it. Identify consumers and move them to keyless authentication or rotate first. Only the exact key from this scan will be targeted."
                else:
                    summary = f"Remove {target['member']} from {target['role']} on project {scan['project_id']}"
                    impact = "This changes the project IAM allow policy and may remove access used by a person or workload. Review dependencies and maintain an emergency recovery path. Other members and bindings will be preserved; an etag protects against stale policy writes."
                plan_id = uuid.uuid4().hex
                db.execute("INSERT INTO remediation_plans(id,scan_id,finding_id,project_id,rule_id,summary,impact,target_json,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)", (plan_id, scan["id"], finding_id, scan["project_id"], finding["rule_id"], summary, impact, json.dumps(target), "proposed", utc_now()))
                return self.send_json({"id": plan_id, "scan_id": scan["id"], "finding_id": finding_id, "project_id": scan["project_id"], "rule_id": finding["rule_id"], "summary": summary, "impact": impact, "target": target, "status": "proposed"}, 201)
        if path.startswith("/api/remediation/") and path.endswith("/apply"):
            plan_id = path.removeprefix("/api/remediation/").removesuffix("/apply")
            try:
                payload = self.read_json()
            except (ValueError, json.JSONDecodeError) as exc:
                return self.send_json({"error": str(exc)}, 400)
            if payload.get("confirm") is not True:
                return self.send_json({"error": "Explicit analyst confirmation is required."}, 400)
            with database() as db:
                row = db.execute("SELECT * FROM remediation_plans WHERE id=?", (plan_id,)).fetchone()
            if not row:
                return self.send_json({"error": "Remediation plan not found."}, 404)
            if row["status"] != "proposed":
                return self.send_json({"error": f"This plan is {row['status']} and cannot be applied again."}, 409)
            if row["project_id"] != configured_gcp_project():
                return self.send_json({"error": "Configured project changed after preview. Create a fresh preview."}, 409)
            with database() as db:
                current = latest_scan(db, "google_cloud")
                if not current or current["id"] != row["scan_id"]:
                    return self.send_json({"error": "A newer Google Cloud scan exists. Create a fresh preview."}, 409)
                claimed = db.execute("UPDATE remediation_plans SET status='applying' WHERE id=? AND status='proposed'", (plan_id,))
                if not claimed.rowcount:
                    return self.send_json({"error": "This plan has already been applied or is being processed."}, 409)
            target = json.loads(row["target_json"])
            try:
                from gcp_provider import GoogleCloudReader
                reader = GoogleCloudReader(row["project_id"])
                if row["rule_id"] in ("GCP-001", "GCP-002", "GCP-003", "GCP-004"):
                    policy = reader.read_project_policy()
                    if not policy.get("etag"):
                        raise ValueError("Google Cloud did not return a policy etag. No change was applied; run a fresh scan.")
                    match = next((binding for binding in policy.get("bindings", []) if binding.get("role") == target.get("role") and binding.get("condition") == target.get("condition") and target.get("member") in binding.get("members", [])), None)
                    if not match:
                        raise ValueError("The exact IAM binding changed since the scan. No changes were applied; scan again.")
                    updated = json.loads(json.dumps(policy))
                    for binding in updated.get("bindings", []):
                        if binding.get("role") == target["role"] and binding.get("condition") == target.get("condition") and target["member"] in binding.get("members", []):
                            binding["members"].remove(target["member"])
                    updated["bindings"] = [binding for binding in updated.get("bindings", []) if binding.get("members")]
                    result = reader.write_project_policy(updated)
                    result_summary = {"message": "Exact principal removed from the matching binding; other members and policy metadata were preserved.", "etag": result.get("etag")}
                elif row["rule_id"] == "GCP-006":
                    if target.get("key_name") is None:
                        raise ValueError("Key name is missing. A fresh scan is required.")
                    result = reader.disable_key(target["key_name"])
                    result_summary = {"message": "Exact user-managed key disabled.", "key_name": target["key_name"]}
                else:
                    return self.send_json({"error": "This remediation is not supported."}, 400)
                with database() as db:
                    db.execute("UPDATE remediation_plans SET status='applied',applied_at=?,result_json=? WHERE id=? AND status='applying'", (utc_now(), json.dumps(result_summary), plan_id))
                    db.execute("UPDATE findings SET status='Reviewed' WHERE id=?", (row["finding_id"],))
                return self.send_json({"status": "applied", "result": result_summary, "message": "Change applied and recorded locally. Run a new scan to verify."})
            except Exception as exc:
                with database() as db:
                    db.execute("UPDATE remediation_plans SET status='failed',applied_at=?,result_json=? WHERE id=? AND status='applying'", (utc_now(), json.dumps({"error": str(exc)[:300]}), plan_id))
                return self.send_json({"error": str(exc)[:300], "status": "failed"}, 409)
        if path == "/api/cloud/project":
            try:
                payload = self.read_json()
            except (ValueError, json.JSONDecodeError) as exc:
                return self.send_json({"error": str(exc)}, 400)
            project_id = str(payload.get("project_id", "")).strip()
            from gcp_provider import validate_project_id
            if not validate_project_id(project_id):
                return self.send_json({"error": "Enter a valid Google Cloud project ID (6–30 lowercase letters, digits, or hyphens)."}, 400)
            with database() as db:
                db.execute("INSERT INTO settings(key,value) VALUES('google_cloud_project_id',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (project_id,))
            return self.send_json({"project_id": project_id, "message": "Project ID saved locally. No credentials were uploaded."})
        if path == "/api/scans":
            try:
                payload = self.read_json()
            except (ValueError, json.JSONDecodeError) as exc:
                return self.send_json({"error": str(exc)}, 400)
            source = payload.get("source", "demo")
            if source not in ("demo", "google_cloud"):
                return self.send_json({"error": "Select demo or google_cloud as the scan source."}, 400)
            with database() as db:
                project_id = configured_gcp_project(db) if source == "google_cloud" else None
            if source == "google_cloud" and not project_id:
                return self.send_json({"error": "Configure a Google Cloud project ID before starting a live scan."}, 400)
            scan_id = uuid.uuid4().hex[:12]
            started = utc_now()
            with JOB_LOCK:
                JOBS[scan_id] = {"id": scan_id, "status": "queued", "progress": 0, "phase": "Queued", "started_at": started, "source": source, "project_id": project_id}
            threading.Thread(target=scan_worker, args=(scan_id,), daemon=True).start()
            return self.send_json({"id": scan_id, "status": "queued", "progress": 0, "phase": "Queued", "started_at": started, "source": source, "project_id": project_id}, 202)
        if path.startswith("/api/findings/") and path.endswith("/review"):
            finding_id = path.removeprefix("/api/findings/").removesuffix("/review")
            try:
                payload = self.read_json()
            except (ValueError, json.JSONDecodeError) as exc:
                return self.send_json({"error": str(exc)}, 400)
            new_status = payload.get("status", "Reviewed")
            if new_status not in ("Open", "Reviewed"):
                return self.send_json({"error": "Supported statuses are Open and Reviewed"}, 400)
            with database() as db:
                cursor = db.execute("UPDATE findings SET status=? WHERE id=?", (new_status, finding_id))
                if not cursor.rowcount:
                    return self.send_json({"error": "Finding not found"}, 404)
                row = db.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
                return self.send_json({"item": dict(row), "message": "Finding status updated locally; no cloud policy was changed."})
        return self.send_json({"error": "Not found"}, 404)


def main():
    initialize_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print("Cloud IAM Risk Analyzer is ready.")
    print(f"Open http://{HOST}:{PORT} in your browser.")
    print("Demo scans inspect synthetic identities only; no cloud account is connected.")
    try:
        webbrowser.open(f"http://{HOST}:{PORT}/")
    except Exception as exc:
        print(f"Could not open the system browser automatically: {exc}")
        print(f"Open http://{HOST}:{PORT}/ in Windows Chrome or Edge.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping local server.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
