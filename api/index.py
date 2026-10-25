"""Vercel serverless entrypoint: exposes the PhishNetra FastAPI app.

Vercel's filesystem is read-only except /tmp, so the scan log and user-edited lists
live there (per instance, reset on cold start). Point PHISHNETRA_DB at a Postgres URL
for durable history.
"""
import os
import sys
from pathlib import Path

os.environ.setdefault("PHISHNETRA_DB", "sqlite:////tmp/phishnetra.db")
os.environ.setdefault("PHISHNETRA_STATE_DIR", "/tmp/phishnetra")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.main import app  # noqa: E402,F401
