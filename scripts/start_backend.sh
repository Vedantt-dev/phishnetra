#!/usr/bin/env bash
# Start the PhishNetra API (serves the built dashboard at /dashboard and demo pages at /demo).
set -euo pipefail
cd "$(dirname "$0")/../backend"
exec ../.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port "${PORT:-8000}" "$@"
