"""Google Cloud IAM inventory with narrowly scoped approved remediation calls.

Scans one configured project. Mutations only run when called by the backend's
explicit analyst-approved remediation endpoint.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from urllib.parse import quote

READ_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
PRIVILEGED_ROLES = {
    "roles/owner", "roles/editor", "roles/iam.securityAdmin",
    "roles/resourcemanager.projectIamAdmin", "roles/iam.serviceAccountAdmin",
}


class GoogleCloudScanError(RuntimeError):
    pass


def validate_project_id(value: str) -> bool:
    return bool(re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", value or ""))


def adc_credentials_present() -> bool:
    explicit = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if explicit:
        return os.path.isfile(explicit)
    appdata = os.environ.get("APPDATA")
    return bool(appdata and os.path.isfile(os.path.join(appdata, "gcloud", "application_default_credentials.json")))


class GoogleCloudReader:
    def __init__(self, project_id: str):
        if not validate_project_id(project_id):
            raise GoogleCloudScanError("Enter a valid Google Cloud project ID (6–30 lowercase letters, digits, or hyphens).")
        try:
            import google.auth
            from google.auth.transport.requests import AuthorizedSession
        except ImportError as exc:
            raise GoogleCloudScanError("Google auth library is not installed. Install dependencies from requirements.txt.") from exc
        try:
            credentials, _ = google.auth.default(scopes=[READ_SCOPE])
        except Exception as exc:
            raise GoogleCloudScanError("Google Cloud credentials were not found. Set up Application Default Credentials on the machine running the backend.") from exc
        self.project_id = project_id
        self.session = AuthorizedSession(credentials)

    def _request(self, method: str, url: str, **kwargs) -> dict:
        try:
            response = self.session.request(method, url, timeout=(8, 30), **kwargs)
        except Exception as exc:
            raise GoogleCloudScanError(f"Could not reach Google Cloud API ({type(exc).__name__}).") from exc
        try:
            data = response.json()
        except ValueError:
            data = {}
        if not response.ok:
            message = data.get("error", {}).get("message", "Google Cloud API request failed") if isinstance(data, dict) else "Google Cloud API request failed"
            if response.status_code in (401, 403):
                message = "Google Cloud denied read access. Check the project IAM policy and required read-only roles."
            raise GoogleCloudScanError(f"HTTP {response.status_code}: {message[:220]}")
        return data

    def read_project_policy(self) -> dict:
        url = f"https://cloudresourcemanager.googleapis.com/v3/projects/{quote(self.project_id, safe='')}:getIamPolicy"
        return self._request("POST", url, json={"options": {"requestedPolicyVersion": 3}})

    def write_project_policy(self, policy: dict) -> dict:
        """Write a caller-reviewed policy after re-reading and preserving its etag."""
        url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{quote(self.project_id, safe='')}:setIamPolicy"
        return self._request("POST", url, json={"policy": policy})

    def disable_key(self, key_name: str) -> dict:
        if not key_name.startswith(f"projects/{self.project_id}/serviceAccounts/") or "/keys/" not in key_name:
            raise GoogleCloudScanError("Refusing to disable a key outside the selected project.")
        url = f"https://iam.googleapis.com/v1/{quote(key_name, safe='/@.')}:disable"
        return self._request("POST", url)

    def list_service_accounts(self) -> list[dict]:
        url = f"https://iam.googleapis.com/v1/projects/{quote(self.project_id, safe='')}/serviceAccounts"
        accounts, token = [], None
        while True:
            params = {"pageSize": 100}
            if token:
                params["pageToken"] = token
            page = self._request("GET", url, params=params)
            accounts.extend(page.get("accounts", []))
            token = page.get("nextPageToken")
            if not token:
                return accounts

    def list_user_managed_keys(self, service_account_email: str) -> list[dict]:
        name = quote(service_account_email, safe="@.")
        url = f"https://iam.googleapis.com/v1/projects/{quote(self.project_id, safe='')}/serviceAccounts/{name}/keys"
        keys, token = [], None
        while True:
            params = {"keyTypes": "USER_MANAGED", "pageSize": 100}
            if token:
                params["pageToken"] = token
            page = self._request("GET", url, params=params)
            keys.extend(page.get("keys", []))
            token = page.get("nextPageToken")
            if not token:
                return keys

    @staticmethod
    def _oldest_enabled_key(keys: list[dict]) -> tuple[int, str | None]:
        active_ages = []
        now = datetime.now(timezone.utc)
        for key in keys:
            if key.get("disabled"):
                continue
            valid_after = key.get("validAfterTime")
            if not valid_after:
                continue
            try:
                created = datetime.fromisoformat(valid_after.replace("Z", "+00:00"))
                active_ages.append((max(0, (now - created).days), key.get("name")))
            except ValueError:
                continue
        return max(active_ages, default=(0, None), key=lambda item: item[0])

    @staticmethod
    def _key_age_days(keys: list[dict]) -> int:
        return GoogleCloudReader._oldest_enabled_key(keys)[0]

    @staticmethod
    def _binding_findings(principal: str, roles: list[dict]) -> list[dict]:
        found = []
        for binding in roles:
            role = binding["role"]
            conditional = bool(binding.get("condition"))
            evidence_condition = f" (conditional binding: {binding['condition'].get('title', 'condition present')})" if conditional else ""
            if principal in ("allUsers", "allAuthenticatedUsers"):
                found.append({"rule_id": "GCP-001", "title": "Public or broadly authenticated project principal", "severity": "Critical", "points": 60, "evidence": f"{principal} is bound to {role}{evidence_condition}.", "recommendation": "Remove the public principal from the project IAM policy after validating intended public access at the resource level.", "target": {"member": principal, "role": role, "condition": binding.get("condition")}})
            elif role == "roles/owner":
                found.append({"rule_id": "GCP-002", "title": "Project Owner role assigned directly", "severity": "Critical", "points": 50, "evidence": f"Principal has direct project role roles/owner{evidence_condition}.", "recommendation": "Replace project Owner with the narrowest task-specific roles after checking dependencies and an emergency recovery path.", "target": {"member": principal, "role": role, "condition": binding.get("condition")}})
            elif role in PRIVILEGED_ROLES:
                found.append({"rule_id": "GCP-003", "title": "High-privilege project role assigned", "severity": "High", "points": 30, "evidence": f"Principal has direct project role {role}{evidence_condition}.", "recommendation": "Review the principal's need and replace the broad role with a resource-scoped role where possible.", "target": {"member": principal, "role": role, "condition": binding.get("condition")}})
            elif role == "roles/editor":
                found.append({"rule_id": "GCP-004", "title": "Project Editor role assigned", "severity": "High", "points": 25, "evidence": f"Principal has direct project role roles/editor{evidence_condition}.", "recommendation": "Replace Editor with task-specific roles; validate workloads before removing permissions.", "target": {"member": principal, "role": role, "condition": binding.get("condition")}})
            elif role.startswith("projects/") or role.startswith("organizations/"):
                found.append({"rule_id": "GCP-005", "title": "Custom project role needs permission review", "severity": "Medium", "points": 10, "evidence": f"Principal has custom role {role}{evidence_condition}; its permission set was not expanded in this scan.", "recommendation": "Review the custom role's included permissions and remove unused or privilege-escalating permissions."})
        return found

    def scan(self, progress=None) -> dict:
        if progress:
            progress(12, "Reading the selected Google Cloud project IAM policy")
        policy = self.read_project_policy()
        bindings_by_principal: dict[str, list[dict]] = {}
        for binding in policy.get("bindings", []):
            normalized = {"role": binding.get("role", ""), "condition": binding.get("condition")}
            for principal in binding.get("members", []):
                bindings_by_principal.setdefault(principal, []).append(normalized)

        if progress:
            progress(34, "Listing service accounts in the selected project")
        accounts = self.list_service_accounts()
        account_by_email = {item.get("email"): item for item in accounts if item.get("email")}
        people = {}
        for principal, roles in bindings_by_principal.items():
            member_type, _, member_value = principal.partition(":")
            account = account_by_email.get(member_value) if member_type == "serviceAccount" else None
            if account:
                identity_id = account.get("uniqueId", member_value)
                name = account.get("displayName") or member_value
                kind = "Service account"
                email = member_value
            else:
                identity_id = principal
                email = member_value or principal
                name = member_value or principal
                kind = {"user": "Human", "group": "Group", "serviceAccount": "Service account", "domain": "Domain"}.get(member_type, "Federated principal")
            people[principal] = {"id": identity_id, "name": name, "email": email, "type": kind, "owner": "Google Cloud project IAM", "mfa": None, "admin": any(item["role"] in PRIVILEGED_ROLES or item["role"] in ("roles/owner", "roles/editor") for item in roles), "permissions": [item["role"] for item in roles], "key_age_days": 0, "inactive_days": 0, "roles": roles, "findings": self._binding_findings(principal, roles)}

        if progress:
            progress(53, f"Checking user-managed keys for {len(accounts)} service accounts")
        account_to_principal = {value.partition(":")[2]: value for value in bindings_by_principal if value.startswith("serviceAccount:")}
        key_errors = 0
        for index, account in enumerate(accounts):
            email = account.get("email")
            if not email:
                continue
            if progress and accounts:
                progress(53 + round(32 * (index + 1) / len(accounts)), f"Checking service-account keys ({index + 1}/{len(accounts)})")
            try:
                keys = self.list_user_managed_keys(email)
            except GoogleCloudScanError as exc:
                if "HTTP 403" in str(exc) or "HTTP 404" in str(exc):
                    key_errors += 1
                    continue
                raise
            age, oldest_key_name = self._oldest_enabled_key(keys)
            principal = account_to_principal.get(email)
            target = people.get(principal) if principal else None
            if target:
                target["key_age_days"] = age
                if age > 180:
                    target["findings"].append({"rule_id": "GCP-006", "title": "Old user-managed service-account key", "severity": "High", "points": 25, "evidence": f"Oldest enabled user-managed key is approximately {age} days old.", "recommendation": "Prefer keyless workload identity or service-account impersonation; rotate or disable a key only after identifying its consumers.", "target": {"key_name": oldest_key_name, "service_account": email}})
                elif age > 90:
                    target["findings"].append({"rule_id": "GCP-007", "title": "Service-account key approaching rotation review", "severity": "Medium", "points": 10, "evidence": f"Oldest enabled user-managed key is approximately {age} days old.", "recommendation": "Plan a keyless migration or rotate the key before the 180-day review threshold.", "target": {"key_name": oldest_key_name, "service_account": email}})
            else:
                # Service accounts without direct project bindings are still inventoried.
                p = f"serviceAccount:{email}"
                key_findings = []
                if age > 180:
                    key_findings.append({"rule_id": "GCP-006", "title": "Old user-managed service-account key", "severity": "High", "points": 25, "evidence": f"Oldest enabled user-managed key is approximately {age} days old.", "recommendation": "Prefer keyless workload identity or service-account impersonation; rotate or disable a key only after identifying its consumers.", "target": {"key_name": oldest_key_name, "service_account": email}})
                elif age > 90:
                    key_findings.append({"rule_id": "GCP-007", "title": "Service-account key approaching rotation review", "severity": "Medium", "points": 10, "evidence": f"Oldest enabled user-managed key is approximately {age} days old.", "recommendation": "Plan a keyless migration or rotate the key before the 180-day review threshold.", "target": {"key_name": oldest_key_name, "service_account": email}})
                people[p] = {"id": account.get("uniqueId", email), "name": account.get("displayName") or email, "email": email, "type": "Service account", "owner": "Google Cloud project", "mfa": None, "admin": False, "permissions": [], "key_age_days": age, "inactive_days": 0, "roles": [], "findings": key_findings}

        identities = []
        for item in people.values():
            score = min(100, sum(finding["points"] for finding in item["findings"]))
            item["score"] = score
            item["level"] = "Critical" if score >= 70 else "High" if score >= 40 else "Medium" if score >= 15 else "Low"
            identities.append(item)

        findings = [(identity, finding) for identity in identities for finding in identity["findings"]]
        total_direct = sum(len(roles) for roles in bindings_by_principal.values())
        privileged = sum(item["role"] in PRIVILEGED_ROLES or item["role"] in ("roles/owner", "roles/editor") for roles in bindings_by_principal.values() for item in roles)
        public_bindings = sum(principal in ("allUsers", "allAuthenticatedUsers") for principal in bindings_by_principal)
        active_keys = [item["key_age_days"] for item in identities if item["type"] == "Service account" and item["key_age_days"] > 0]
        controls = [
            {"name": "Direct project roles reviewed", "framework": "Project IAM policy", "percent": 100 if policy else 0, "status": "Compliant" if policy else "Attention"},
            {"name": "Owner/editor role footprint", "framework": "Least privilege", "percent": max(0, 100 - round(100 * privileged / max(1, total_direct))), "status": "Attention" if privileged else "Compliant"},
            {"name": "Public project principals", "framework": "External exposure", "percent": 0 if public_bindings else 100, "status": "Attention" if public_bindings else "Compliant"},
            {"name": "User-managed key rotation", "framework": "IAM key hygiene", "percent": round(100 * sum(age <= 180 for age in active_keys) / len(active_keys)) if active_keys else 100, "status": "Attention" if any(age > 180 for age in active_keys) else "Compliant"},
            {"name": "Human MFA status", "framework": "Not assessed", "percent": None, "status": "Not assessed"},
        ]
        compliance = {"percent": round(sum(control["percent"] for control in controls if control["percent"] is not None) / max(1, sum(control["percent"] is not None for control in controls))), "controls": controls}
        if progress:
            progress(94, "Scoring project-level IAM findings")
        caveats = ["Project-level allow policy only; inherited organization/folder policies and deny policies are not expanded.", "Google Cloud IAM project APIs do not provide human MFA enrollment or sign-in activity; those signals are not inferred."]
        if key_errors:
            caveats.append(f"Key metadata unavailable for {key_errors} service account(s) due to permission or resource errors.")
        return {"identities": identities, "findings": findings, "compliance": compliance, "caveats": caveats, "project_id": self.project_id}
