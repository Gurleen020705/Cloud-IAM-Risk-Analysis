# Architecture

The local application has one Python server for both the static dashboard and JSON API. On Vercel, the dashboard is served as static files and `/api/*` is routed to a Python serverless function.

## Request flow

1. Locally, `run.bat` starts `server.py`, which calls `backend/app.py`; that server serves the frontend and handles `/api/*`.
2. On Vercel, `vercel.json` serves `frontend/` and rewrites `/api/*` to `api/index.py`.
3. Both API entry points use `backend/scanner.py`, which loads `data/sample_iam_identities.json` for synthetic sample scans.
4. The frontend renders scan metrics, identities, findings, and review status.

## API routes

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Local API status and demo-mode indicator |
| GET | `/api/dashboard` | Latest in-memory scan results |
| POST | `/api/scan` | Run the sample IAM rules |
| POST | `/api/findings/{finding_id}/review` | Mark a finding reviewed in the current server session |

The local server holds scan results and review status in memory until it stops. Vercel functions are stateless: scan results and review status are not persisted by the API, and review status is tracked only in the visitor's browser session. The default deployment uses no cloud credentials or third-party Python packages.

On Vercel, `GET /api/dashboard` returns an empty initial state because function memory is not durable. `POST /api/scan` returns scan results directly to the current browser, and `POST /api/findings/{finding_id}/review` returns `409` because review state is browser-only.
