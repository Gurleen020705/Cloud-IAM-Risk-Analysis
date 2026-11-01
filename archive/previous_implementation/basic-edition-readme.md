# Cloud IAM Risk Analyzer — Basic

## Run the whole project

From the main project folder, run this in PowerShell:

```powershell
.\Start-IAM-Analyzer.bat
```

To start this backend directly from this folder with a registered Python 3 installation, run:

```powershell
py -3 -E server.py
```

The Python standard-library backend serves this UI, opens the Windows default browser, and prints the exact address after binding to a port. `-E` ignores mis-set `PYTHON*` environment variables that can cause the prefix warning. Keep the terminal open. If port 8000 is already occupied, the server automatically tries ports 8001–8019.

You can also open `index.html` directly. That mode runs the sample scan in the browser without any backend or localhost calls.

## What this starter does

- Shows a dark security analyst dashboard with scan progress, identity list, findings, search and severity filter.
- Runs transparent checks against synthetic demo identities: public principals, Owner/Editor roles, sample MFA state, and old service-account keys.
- Marks findings reviewed locally.
- Uses no pip packages, no cloud credentials, and makes no Google Cloud changes.

The sample results are for learning only. They do not represent a real cloud scan, security certification, or real IAM advice for your production environment.

## Files

- `server.py` — standard-library web server and small JSON API. Starts with `py server.py`.
- `index.html` — dashboard structure and controls.
- `styles.css` — responsive dark theme and visual indicators.
- `app.js` — sample data, browser fallback, demo checks, scan progress, filters, and review action.
