"""Configuration loading and shared paths."""
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict

import yaml

BACKEND_DIR = Path(__file__).resolve().parent.parent
PROJECT_DIR = BACKEND_DIR.parent
DATA_DIR = BACKEND_DIR / "data"
MODELS_DIR = BACKEND_DIR / "models"
DEMO_DIR = PROJECT_DIR / "demo"
DASHBOARD_DIST = PROJECT_DIR / "dashboard" / "dist"

# User-modified lists (feedback blocklist / allowlist) live here; tests point it elsewhere.
STATE_DIR = Path(os.environ.get("PHISHNETRA_STATE_DIR", DATA_DIR))
STATE_DIR.mkdir(parents=True, exist_ok=True)

CONFIG_PATH = Path(os.environ.get("PHISHNETRA_CONFIG", BACKEND_DIR / "config.yaml"))
DB_URL = os.environ.get("PHISHNETRA_DB", f"sqlite:///{BACKEND_DIR / 'phishnetra.db'}")

# Offline mode disables every outbound network lookup (WHOIS, TLS, feeds). Used by tests.
OFFLINE = os.environ.get("PHISHNETRA_OFFLINE", "0") == "1"


@lru_cache(maxsize=1)
def get_config() -> Dict[str, Any]:
    with open(CONFIG_PATH) as fh:
        return yaml.safe_load(fh)
