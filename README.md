# Cloud IAM Risk Analyzer

A local learning application for reviewing cloud IAM risks. Its default mode uses a bundled synthetic dataset; it does not connect to Google Cloud or modify permissions.

## Run on Windows

Open PowerShell in this project folder and run:

```powershell
.\run.bat
```

Keep the terminal window open. The launcher prints the dashboard address and opens it in your browser. It prefers `http://127.0.0.1:8004/`; stop the backend with `Ctrl+C`. No `pip install` step is needed. If Python is installed and registered with Windows, you can also run `py -3 -E server.py`.

You may open `frontend/index.html` directly for browser-only sample mode. This mode does not use the backend API.

## Project layout

```text
backend/
  app.py                  Local HTTP server and JSON API
  scanner.py              Explainable IAM sample-risk rules
data/
  sample_iam_identities.json  Synthetic identities used by the demo
frontend/
  index.html              Dashboard structure
  assets/css/dashboard.css  Layout, theme, and responsive styles
  assets/js/dashboard.js    UI behavior, sample fallback, and API calls
docs/
  ARCHITECTURE.md         Request flow and API overview
archive/
  previous_implementation/ Preserved older project files; not used at runtime
server.py                 Python entry point
run.bat                   Windows one-command launcher
```

## What the sample scanner checks

- Public principals such as `allUsers`.
- Broad Owner and Editor roles.
- A sample administrator without MFA.
- An old sample service-account key.
- MFA disabled, keys nearing rotation, inactive identities retaining access, elevated external access, simulated unused roles, and unusual synthetic sign-in activity.

The dataset contains fictional identities across three illustrative regions. Each sample scan makes a new synthetic snapshot by varying selected MFA and service-key values in memory. The source JSON is not modified. The unused-role signal is invented training data, not evidence from real audit logs.

The dashboard explains finding evidence and suggested review steps. Its scan history is saved in the browser. All displayed results are simulated sample findings, not a real cloud assessment or compliance certification. “Simulate fix” only changes the current browser session and needs a verification scan before showing a risk as cleared. No cloud settings are changed by sample mode.

When opened through the local sample API, the dashboard runs a new synthetic scan on each page load. The sample scenario rotates in the browser so the IAM risk score and findings can visibly change after refresh; no real cloud data is involved.

The dashboard background includes a low-contrast decorative code-typing effect; it does not run those displayed snippets or connect to a cloud account.

## Local API

- `GET /api/health` — confirms that the local demo API is available.
- `GET /api/dashboard` — returns the most recent scan results.
- `POST /api/scan` — analyzes the bundled sample data.
- `POST /api/findings/{finding_id}/review` — marks a demo finding reviewed in memory.

The local server binds to `127.0.0.1` and prints that exact IPv4 address (not `localhost`, which may resolve to IPv6 `::1` on Windows). It prefers port `8004`, then tries `8005`–`8023` if occupied. For public sample-demo hosting, see [Deploy to Vercel](#deploy-to-vercel).

## Deploy to Vercel

The Vercel configuration serves the static dashboard from `frontend/` and routes `/api/*` to a Python serverless function. The default deployment uses synthetic sample data and needs no Google Cloud credentials.

### One-time setup

1. Create a Vercel account, install the Vercel CLI locally with `npm install --global vercel`, and sign in with `vercel login`.
2. From the repository folder, run `vercel link` and create or select a Vercel project. Keep the generated `.vercel/` folder local; it is ignored by Git.
3. In Vercel account settings, create a token with access to that project.
4. In the GitHub repository, open **Settings → Secrets and variables → Actions** and add these repository secrets:
   - `VERCEL_TOKEN`: the Vercel token.
   - `VERCEL_ORG_ID` and `VERCEL_PROJECT_ID`: copy these from `.vercel/project.json` created by `vercel link`.
5. Push this workflow and the Vercel configuration to the `main` branch. The GitHub Actions workflow runs Python checks on pull requests and deploys to production after a successful push to `main`. You can also start a validation run from **Actions → Deploy to Vercel → Run workflow**; production deployment is limited to pushes to `main`.

The dashboard is public once deployed. Do not configure `GCP_PROJECT_ID` or cloud credentials for this unauthenticated demo deployment: doing so would expose the read-only scan endpoint publicly. Vercel functions are stateless, so reviewed-finding status and the latest scan are not persisted by the API; browser-session state remains local to each visitor. To avoid competing production deployments, use this workflow as the production deployer rather than enabling a second automatic production deploy from Vercel's Git integration.

To test the API route handlers locally without deploying, run `python -m unittest discover -s tests -v`.
