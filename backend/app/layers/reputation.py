"""Layer 1 — Reputation & threat intelligence.

Combines a curated allowlist (Tranco top sites), a blocklist (OpenPhish feed + user
reports), WHOIS domain age, TLS certificate checks and TLD reputation.
"""
import logging
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Optional, Set

import httpx

from app.config import DATA_DIR, OFFLINE, STATE_DIR, get_config
from app.features.domain import ParsedURL, parse_url
from app.features.url_features import FREE_HOSTING
from app.layers.base import LayerResult

log = logging.getLogger(__name__)
_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="reputation")


def _read_list(path: Path) -> Set[str]:
    if not path.exists():
        return set()
    return {
        line.strip().lower()
        for line in path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }


class ThreatIntel:
    """Thread-safe in-memory allow/block lists backed by text files in backend/data."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.allow: Set[str] = set()
        self.block_domains: Set[str] = set()
        self.block_urls: Set[str] = set()
        self.reload()

    def reload(self) -> None:
        allow = _read_list(DATA_DIR / "allowlist_seed.txt") | _read_list(DATA_DIR / "allowlist.txt")
        allow |= _read_list(STATE_DIR / "user_allowlist.txt")
        block_domains, block_urls = set(), set()
        feeds = set()
        for d in {DATA_DIR, STATE_DIR}:
            feeds |= _read_list(d / "blocklist.txt") | _read_list(d / "openphish_feed.txt")
        for entry in feeds:
            if "/" in entry.split("://", 1)[-1].rstrip("/"):
                block_urls.add(entry.rstrip("/"))
            block_domains.add(parse_url(entry).host)
        with self._lock:
            self.allow, self.block_domains, self.block_urls = allow, block_domains, block_urls

    def is_allowlisted(self, p: ParsedURL) -> bool:
        if p.registrable in FREE_HOSTING or p.host in FREE_HOSTING:
            return False
        with self._lock:
            return p.registrable in self.allow

    def is_blocklisted(self, url: str) -> bool:
        p = parse_url(url)
        with self._lock:
            return p.host in self.block_domains or p.url.lower().rstrip("/") in self.block_urls

    def add_block(self, url: str) -> None:
        host = parse_url(url).host
        with self._lock:
            if host in self.block_domains:
                return
            self.block_domains.add(host)
        with open(STATE_DIR / "blocklist.txt", "a") as fh:
            fh.write(host + "\n")

    def add_allow(self, registrable: str) -> None:
        with self._lock:
            self.allow.add(registrable)
        with open(STATE_DIR / "user_allowlist.txt", "a") as fh:
            fh.write(registrable + "\n")

    def blocklist(self):
        with self._lock:
            return sorted(self.block_domains)

    def refresh_openphish(self) -> int:
        cfg = get_config()["reputation"]
        resp = httpx.get(cfg["openphish_feed_url"], timeout=20)
        resp.raise_for_status()
        (STATE_DIR / "openphish_feed.txt").write_text(resp.text)
        self.reload()
        return len(resp.text.splitlines())


intel = ThreatIntel()


@lru_cache(maxsize=2048)
def domain_age_days(registrable: str) -> Optional[int]:
    import whois  # python-whois; imported lazily because it is slow to import

    try:
        record = whois.whois(registrable)
    except Exception:  # noqa: BLE001 — WHOIS servers fail in many creative ways
        return None
    raw = record.creation_date
    # Registrars return one date or a list mixing naive and tz-aware datetimes.
    dates = [d if d.tzinfo else d.replace(tzinfo=timezone.utc)
             for d in (raw if isinstance(raw, list) else [raw]) if isinstance(d, datetime)]
    if not dates:
        return None
    return (datetime.now(timezone.utc) - min(dates)).days


@lru_cache(maxsize=2048)
def tls_status(host: str, timeout: float) -> str:
    """'valid', 'invalid' (cert fails verification) or 'none' (no TLS on 443)."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return "valid"
    except ssl.SSLCertVerificationError:
        return "invalid"
    except (OSError, ssl.SSLError):
        return "none"


def _result_by(future, deadline: float):
    if future is None:
        return None
    try:
        return future.result(timeout=max(0.0, deadline - time.monotonic()))
    except FutureTimeout:
        return None


def analyze(url: str, network: bool = True, budget: Optional[float] = None) -> LayerResult:
    cfg = get_config()
    rep_cfg = cfg["reputation"]
    p = parse_url(url)
    result = LayerResult(name="reputation", score=0.0)
    result.details["registrable"] = p.registrable

    if intel.is_blocklisted(url):
        result.score = 100.0
        result.reasons.append("Listed in phishing threat-intelligence blocklist")
        result.details["blocklisted"] = True
        return result

    if intel.is_allowlisted(p):
        result.details["allowlisted"] = True
        result.reasons.append(f"{p.registrable} is a verified high-reputation domain")
        return result

    score = 15.0  # zero trust: unknown domains start with a small amount of risk
    result.reasons.append("Domain is not on the verified allowlist")

    if p.is_ip:
        score += 25
        result.reasons.append("Navigation target is a bare IP address")
    last_label = p.suffix.split(".")[-1] if p.suffix else ""
    if last_label in cfg.get("suspicious_tlds", []):
        score += 20
        result.reasons.append(f".{last_label} has poor TLD reputation")
    if p.registrable in FREE_HOSTING or any(p.host.endswith("." + h) for h in FREE_HOSTING):
        score += 15
        result.reasons.append("Free hosting platform — anyone can publish here")

    if network and not OFFLINE and not p.is_ip:
        # WHOIS and TLS run in parallel under one time budget. Lookups that miss the budget
        # keep running and land in the cache, so the post-load (DOM) scan still benefits.
        deadline = time.monotonic() + (budget or rep_cfg["whois_timeout_seconds"])
        age_f = _pool.submit(domain_age_days, p.registrable) if rep_cfg.get("whois_enabled", True) else None
        tls_f = (_pool.submit(tls_status, p.host, rep_cfg["tls_timeout_seconds"])
                 if rep_cfg.get("tls_enabled", True) and p.scheme == "https" else None)
        age = _result_by(age_f, deadline)
        status = _result_by(tls_f, deadline)
        result.details["domain_age_days"] = age
        result.details["tls"] = status
        if age is not None and age < rep_cfg["young_domain_days"]:
            score += 35
            result.reasons.append(f"Domain registered only {age} days ago")
        elif age is not None and age < 365:
            score += 10
            result.reasons.append(f"Domain is less than a year old ({age} days)")
        elif age is not None:
            score -= 10
        if status == "invalid":
            score += 30
            result.reasons.append("TLS certificate failed verification")

    result.score = float(max(0.0, min(100.0, score)))
    return result
