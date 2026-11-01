"""One-command launcher for the simple Cloud IAM Risk Analyzer project."""
from pathlib import Path
import runpy

BASIC_SERVER = Path(__file__).resolve().parent / "Cloud-IAM-Risk-Analyzer-Basic" / "server.py"

if not BASIC_SERVER.is_file():
    raise SystemExit(f"Basic project backend not found: {BASIC_SERVER}")

print("Launching the Basic Edition from Cloud-IAM-Risk-Analyzer-Basic...", flush=True)
runpy.run_path(str(BASIC_SERVER), run_name="__main__")
