"""Orchestrates the detection layers, the policy engine, caching and persistence."""
import json
import logging
import threading
import time
from typing import Dict, Optional, Tuple

from app import db
from app.config import get_config
from app.features.domain import normalize_url, parse_url
from app.layers import brand, dom_model, reputation, url_model
from app.layers.base import LayerResult
from app.policy import decide
from app.schemas import DomScanRequest

log = logging.getLogger(__name__)


class TTLCache:
    def __init__(self, maxsize: int = 5000):
        self._data: Dict[str, Tuple[float, dict]] = {}
        self._lock = threading.Lock()
        self.maxsize = maxsize

    def get(self, key: str) -> Optional[dict]:
        with self._lock:
            hit = self._data.get(key)
            if hit and hit[0] > time.time():
                return hit[1]
            self._data.pop(key, None)
            return None

    def set(self, key: str, value: dict, ttl: float) -> None:
        with self._lock:
            if len(self._data) >= self.maxsize:
                self._data.pop(next(iter(self._data)))
            self._data[key] = (time.time() + ttl, value)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


cache = TTLCache()


def _safe(name: str, fn, *args, **kwargs) -> LayerResult:
    """A failing layer is reported as unavailable instead of failing the whole scan."""
    try:
        return fn(*args, **kwargs)
    except Exception:  # noqa: BLE001
        log.exception("layer %s failed", name)
        return LayerResult(name=name, score=None, reasons=[f"{name} layer unavailable (internal error)"])


def _persist(result: dict, source: str) -> dict:
    with db.SessionLocal() as session:
        row = db.Scan(
            url=result["url"], domain=result["domain"], stage=result["stage"], source=source,
            risk=result["risk"], verdict=result["verdict"], trust=result["trust"],
            impersonated_brand=result["impersonated_brand"],
            layers_json=json.dumps(result["layers"]), reasons_json=json.dumps(result["reasons"]),
            latency_ms=result["latency_ms"],
        )
        session.add(row)
        session.commit()
        result["scan_id"] = row.id
        result["created_at"] = row.created_at
    return result


def _build(url: str, stage: str, layers, has_credential_form: bool, started: float) -> dict:
    decision = decide(layers, has_credential_form=has_credential_form)
    return {
        "scan_id": None,
        "url": url,
        "domain": parse_url(url).host,
        "stage": stage,
        "risk": decision.risk,
        "verdict": decision.verdict,
        "trust": decision.trust,
        "impersonated_brand": decision.impersonated_brand,
        "reasons": decision.reasons,
        "layers": decision.layers,
        "latency_ms": round((time.perf_counter() - started) * 1000, 1),
        "cached": False,
    }


def scan_url(url: str, source: str = "api", network: bool = True) -> dict:
    """Pre-navigation scan: everything that can be judged from the URL alone."""
    url = normalize_url(url)
    cached = cache.get(f"url:{url}")
    if cached:
        return {**cached, "cached": True}
    started = time.perf_counter()
    budget = get_config()["reputation"]["url_stage_budget_seconds"]
    layers = [
        _safe("reputation", reputation.analyze, url, network=network, budget=budget),
        _safe("url_model", url_model.analyze, url),
        LayerResult(name="dom_model", score=None, reasons=["Awaiting page content"]),
        _safe("brand", brand.analyze, url),
    ]
    result = _persist(_build(url, "url", layers, False, started), source)
    cache.set(f"url:{url}", result, get_config()["cache_ttl_seconds"])
    return result


def scan_dom(req: DomScanRequest, network: bool = True) -> dict:
    """Post-load scan: adds page-structure and content impersonation evidence."""
    url = normalize_url(req.url)
    started = time.perf_counter()
    has_password = bool(req.features.get("HasPasswordField"))
    layers = [
        _safe("reputation", reputation.analyze, url, network=network),
        _safe("url_model", url_model.analyze, url),
        _safe("dom_model", dom_model.analyze, url, req.title, req.features),
        _safe("brand", brand.analyze, url, title=req.title, text=req.text, has_password=has_password,
              favicon_url=req.favicon_url),
    ]
    return _persist(_build(url, "dom", layers, has_password, started), req.source)
