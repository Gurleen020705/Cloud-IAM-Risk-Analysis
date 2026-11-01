# Sentinel IAM — Cloud IAM Risk Analyzer

Sentinel IAM is a security analyst dashboard for spotting risky Google Cloud project IAM access, understanding why it was flagged, and reviewing a precise proposed fix.

## “Online” ka matlab

The app backend runs on **your computer** at `127.0.0.1:8000`; it is not a public website deployed to the internet. When configured, that local backend uses Google Application Default Credentials (ADC) to contact Google Cloud APIs over the internet and scan the one project you selected. The browser never sends a private key or access token to the dashboard. The project ID and scan results are stored locally in this folder's SQLite database.

Until Google Cloud project ID and ADC are configured, sample demo mode is synthetic data. A browser-only `index.html` preview is also synthetic and cannot access the real Google Cloud APIs.

## Capabilities

- Dark analyst console with live scan progress, identity inventory, risk score, alerts, history chart and control posture.
- Real, read-only Google Cloud scan of direct project IAM allow-policy bindings, service accounts and user-managed service-account key metadata.
- Evidence-linked rules for public principals, Owner/Editor and selected high-privilege project roles, custom-role review, and old user-managed keys.
- Remediation preview for supported project binding findings and old keys. The analyst sees the exact target and impact, checks an explicit approval box, and clicks **Approve & apply**. Backend re-reads current state and rejects stale scan/policy evidence. No change is made by scanning or previewing.
- Local SQLite audit record of scans, findings, reviews and remediation plan status.

Automated fixes are limited to removing one exact principal from one exact project-level binding, or disabling one exact user-managed key. This prototype does not design replacement least-privilege roles, rotate keys, alter inherited policies, or automatically remediate custom roles and other findings. Review workload impact and change approvals before using write permissions.

## Google Cloud setup

1. Install Python 3 and the Google Cloud CLI on the computer that runs this backend.
2. In this project directory, install the Python dependency:

   ```powershell
   python -m pip install -r requirements.txt
   ```

3. Authenticate ADC on that same computer:

   ```powershell
   gcloud auth application-default login
   ```

4. For scan only, grant the authenticated identity `roles/browser` (project IAM policy read) and `roles/iam.serviceAccountViewer` (service-account/key metadata read), or an equivalent custom role. The role permissions and service account key read requirements are documented by Google Cloud.
5. Run `Start-IAM-Analyzer.bat`, click **Configure GCP**, enter the Google Cloud project ID, select **Google Cloud**, then click **Start scan**.
6. To allow a particular fix, separately grant only its required write permission. IAM binding changes need `resourcemanager.projects.setIamPolicy`; key disable needs `iam.serviceAccountKeys.disable`. These permissions are powerful. Do not grant them if you only want scanning. The app will not use them unless you explicitly approve an exact preview.

The project ID is not a secret. Never paste service-account private keys, access tokens or ADC files into this chat or the browser. The app uses ADC from the local machine and does not upload credential files.

## Assessment limitations

- One selected project, direct allow-policy only. Inherited organization/folder policy, deny policies, group membership expansion, effective access from other sources, human MFA and sign-in activity are not assessed.
- Custom roles are identified but their full permission set is not analyzed in this prototype.
- Compliance numbers are indicative control mappings, not certification or proof of compliance.
- Google Cloud key disable prevents that key from authenticating; a workload relying on it can fail. Google documents that disabled keys can be re-enabled. Identify consumers before approving.
- This is a local prototype, not a hardened multi-user service. Keep it bound to loopback and run it only on a trusted analyst workstation.

## Stack and purpose

| Technology | Purpose |
| --- | --- |
| HTML | Dashboard structure, dialogs, forms and findings |
| CSS | Responsive dark theme, neon accents, charts, scanner and alert states |
| JavaScript | UI interactions, REST requests, scan progress polling and approval workflow |
| Python standard library | Loopback HTTP API, scan worker, rule engine and REST requests orchestration |
| `google-auth` | Local ADC credential discovery and authenticated Google API requests |
| SQLite | Local scan history, finding evidence, identity snapshots and remediation audit trail |
| SVG | Lightweight scan history chart |

## Local/demo mode

Run `Start-IAM-Analyzer.bat` from the project folder to start the backend. It uses the bundled Python runtime when available; otherwise, it tries `py -3` and then `python`. The backend opens your Windows default browser after starting. Keep its terminal window open. If the backend is already running, use `Open-Dashboard.bat` to open it in your Windows default browser. The Codex in-app browser may not be able to connect to a local server. In PowerShell, use the bundled runtime explicitly if the `python` command opens the Microsoft Store alias:

```powershell
& "$env:USERPROFILE\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" server.py
```

Then open `http://127.0.0.1:8000`. If the backend is stopped, opening `index.html` directly shows an offline synthetic preview; it cannot perform a live Google scan.

## Files

- `server.py` — local API, scan storage, findings, plan preview and explicit apply endpoints.
- `gcp_provider.py` — ADC-authenticated Google Cloud reader and narrow remediation API calls.
- `index.html`, `styles.css`, `app.js` — dashboard and analyst interactions.
- `requirements.txt` — Google authentication dependency.
- `Start-IAM-Analyzer.bat` — starts the loopback backend and opens it in the browser.
- `Open-Dashboard.bat` — opens the already-running backend in the Windows default browser.
- `iam_analyzer.sqlite3` — local generated data; ignored by Git.
