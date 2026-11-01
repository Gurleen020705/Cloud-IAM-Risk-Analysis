# Architecture

The application has one local Python server for both the static dashboard and JSON API. This avoids CORS configuration and keeps the beginner setup to one command.

## Request flow

1. `run.bat` starts the root `server.py` entry point.
2. `server.py` calls `backend/app.py`.
3. `backend/app.py` serves `frontend/` and handles the `/api/*` routes.
4. `backend/scanner.py` loads `data/sample_iam_identities.json` and applies transparent rule checks.
5. The frontend renders scan metrics, identities, findings, and review status.

## API routes

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Local API status and demo-mode indicator |
| GET | `/api/dashboard` | Latest in-memory scan results |
| POST | `/api/scan` | Run the sample IAM rules |
| POST | `/api/findings/{finding_id}/review` | Mark a finding reviewed in the current server session |

Scan results and review status are held in memory and reset when the server stops. The project uses no database, cloud credentials, or third-party Python packages in this learning version.
