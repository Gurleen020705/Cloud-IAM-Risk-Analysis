"""Explainable checks for the bundled synthetic IAM sample dataset."""
from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import os
import urllib.error
import urllib.parse
import urllib.request

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_DATA_FILE = PROJECT_ROOT / "data" / "sample_iam_identities.json"
SAMPLE_SCAN_SEQUENCE = 0


def load_sample_identities() -> list[dict[str, Any]]:
    """Load the checked-in demo identities; this function makes no cloud calls."""
    with SAMPLE_DATA_FILE.open(encoding="utf-8") as sample_file:
        identities = json.load(sample_file)
    if not isinstance(identities, list):
        raise ValueError("Sample IAM data must be a JSON list.")
    return identities


def scan_sample() -> dict[str, Any]:
    """Apply transparent demo rules and return dashboard-ready results."""
    global SAMPLE_SCAN_SEQUENCE
    SAMPLE_SCAN_SEQUENCE += 1
    phase = SAMPLE_SCAN_SEQUENCE
    identities: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    source_identities = load_sample_identities()
    human_index = 0
    service_index = 0
    service_key_ages = (245, 128, 218, 74, 267, 154)
    for original in source_identities:
        identity = deepcopy(original)
        # Each demo scan represents a different fictional snapshot. The source
        # JSON is never edited; only this in-memory copy receives the variation.
        if identity.get("type") == "Human":
            identity["mfa"] = ((human_index + phase) % 4) != 0
            human_count = sum(item.get("type") == "Human" for item in source_identities)
            identity["suspicious_login"] = (human_index + phase) % max(1, human_count) == 0
            human_index += 1
        elif identity.get("type") == "Service account":
            identity["key_age_days"] = service_key_ages[(phase + service_index) % len(service_key_ages)]
            service_index += 1
        roles = identity.get("roles", [])
        checks = [
            (
                "allUsers" in roles or "allAuthenticatedUsers" in roles,
                "IAM-001",
                "Public principal has access",
                "Critical",
                50,
                "Public principals can expose resources to anyone on the internet.",
            ),
            (
                "roles/owner" in roles,
                "IAM-002",
                "Project Owner role assigned",
                "Critical",
                45,
                "Owner includes broad project permissions; review whether this access is needed.",
            ),
            (
                "roles/editor" in roles,
                "IAM-003",
                "Project Editor role assigned",
                "High",
                30,
                "Editor allows broad changes across project resources.",
            ),
            (
                identity.get("type") == "Human"
                and "roles/owner" in roles
                and identity.get("mfa") is False,
                "IAM-004",
                "Human administrator without MFA",
                "High",
                25,
                "A human administrator has no MFA in this sample record.",
            ),
            (
                identity.get("type") == "Service account"
                and identity.get("key_age_days", 0) > 180,
                "IAM-005",
                "Service account key older than 180 days",
                "High",
                25,
                f"A user-managed service-account key is {identity.get('key_age_days', 0)} days old.",
            ),
            (identity.get("type") == "Human" and identity.get("mfa") is False,
             "IAM-006", "MFA is disabled", "High", 25,
             "This human identity has MFA disabled in the synthetic dataset."),
            (identity.get("type") == "Service account" and identity.get("key_age_days", 0) > 90 and identity.get("key_age_days", 0) <= 180,
             "IAM-007", "Service account key nearing rotation", "Medium", 15,
             f"User-managed key age is {identity.get('key_age_days', 0)} days; review rotation."),
            (identity.get("status") == "Inactive" and bool(roles),
             "IAM-008", "Inactive identity still has access", "High", 25,
             "Inactive identity retains one or more project roles."),
            (identity.get("external") is True and not any(role in ("roles/viewer", "roles/browser") for role in roles),
             "IAM-009", "External identity has elevated access", "High", 25,
             "External identity has a role broader than basic viewing."),
            (identity.get("unused_role") is True,
             "IAM-010", "Potentially unused role assignment", "Medium", 15,
             "Synthetic access review data marks this role as unused for 90 days."),
            (identity.get("suspicious_login") is True,
             "IAM-011", "Unusual sign-in signal (synthetic)", "High", 25,
             "Synthetic demo activity marks this sign-in as unusual; no real sign-in logs were read."),
        ]

        identity_findings = []
        for matched, rule_id, title, severity, points, evidence in checks:
            if not matched:
                continue
            finding = {
                "id": f"{identity['id']}:{rule_id}",
                "identity_id": identity["id"],
                "identity_name": identity["name"],
                "rule_id": rule_id,
                "title": title,
                "severity": severity,
                "points": points,
                "evidence": evidence,
                "recommendation": (
                    "Review the access with its owner and use the narrowest "
                    "permissions that still support the work."
                ),
                "status": "Open",
            }
            identity_findings.append(finding)
            findings.append(finding)

        identity["findings"] = identity_findings
        identity["score"] = min(100, sum(item["points"] for item in identity_findings))
        score = identity["score"]
        identity["level"] = (
            "Critical" if score >= 70 else
            "High" if score >= 40 else
            "Medium" if score >= 15 else
            "Low"
        )
        identities.append(identity)

    critical_count = sum(item["severity"] == "Critical" for item in findings)
    high_count = sum(item["severity"] == "High" for item in findings)
    return {
        "mode": "sample-demo",
        "scan_number": SAMPLE_SCAN_SEQUENCE,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "identities": identities,
        "findings": findings,
        "metrics": {
            "identity_count": len(identities),
            "finding_count": len(findings),
            "critical_count": critical_count,
            "high_count": high_count,
            "risk_score": round(
                sum(item["score"] for item in identities) / max(1, len(identities))
            ),
            "compliance": max(0, 100 - critical_count * 15 - high_count * 8),
        },
    }


def scan_gcp_project(project_id: str) -> dict[str, Any]:
    """Read one project's IAM policy through ADC; makes no cloud changes."""
    if not project_id or not all(c.isalnum() or c in '-:' for c in project_id):
        raise ValueError("Enter a valid Google Cloud project ID.")
    try:
        import google.auth
        from google.auth.transport.requests import AuthorizedSession
    except ImportError as error:
        raise RuntimeError("Google Cloud support is not installed. Install requirements-gcp.txt.") from error
    credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    session = AuthorizedSession(credentials)
    url = "https://cloudresourcemanager.googleapis.com/v3/projects/" + urllib.parse.quote(project_id, safe="") + ":getIamPolicy"
    response = session.post(url, json={"options": {"requestedPolicyVersion": 3}}, timeout=20)
    if response.status_code in (401, 403):
        raise PermissionError("Google rejected access. Sign in with ADC and grant this account read access to the project's IAM policy.")
    response.raise_for_status()
    policy = response.json()
    identities = []
    for binding_index, binding in enumerate(policy.get("bindings", [])):
        role = binding.get("role", "")
        for member_index, member in enumerate(binding.get("members", [])):
            identities.append({"id": f"{binding_index}-{member_index}", "name": member, "email": member,
                "type": "Service account" if member.startswith("serviceAccount:") else "Human" if member.startswith("user:") else "External principal",
                "owner": project_id, "roles": [role], "mfa": None, "key_age_days": 0})
    findings = []
    for identity in identities:
        role = identity["roles"][0]
        matches = []
        if role in ("roles/owner", "roles/editor"):
            matches.append(("IAM-002" if role == "roles/owner" else "IAM-003", "Project Owner role assigned" if role == "roles/owner" else "Project Editor role assigned", "Critical" if role == "roles/owner" else "High", "Broad project role found in IAM policy."))
        if role in ("allUsers", "allAuthenticatedUsers"):
            matches.append(("IAM-001", "Public principal has access", "Critical", f"{role} is a member of {project_id}'s project IAM policy."))
        identity["findings"] = []
        for rule_id, title, severity, evidence in matches:
            finding = {"id": f"{identity['id']}:{rule_id}", "identity_id": identity["id"], "identity_name": identity["name"], "rule_id": rule_id, "title": title, "severity": severity, "points": 45 if severity == "Critical" else 30, "evidence": evidence, "recommendation": "Review with the access owner and use the narrowest required role.", "status": "Open"}
            identity["findings"].append(finding)
            findings.append(finding)
        identity["score"] = min(100, sum(x["points"] for x in identity["findings"]))
        identity["level"] = "Critical" if identity["score"] >= 70 else "High" if identity["score"] >= 40 else "Medium" if identity["score"] >= 15 else "Low"
    critical = sum(x["severity"] == "Critical" for x in findings)
    high = sum(x["severity"] == "High" for x in findings)
    return {"timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"), "identities": identities, "findings": findings,
        "metrics": {"identity_count": len(identities), "finding_count": len(findings), "critical_count": critical, "high_count": high,
        "risk_score": round(sum(x["score"] for x in identities) / max(1, len(identities))), "compliance": max(0, 100-critical*15-high*8)},
        "mode": "gcp-read-only", "project_id": project_id, "scope_note": "Scanned project IAM policy bindings only. No other resource types were checked."}
