"""Layer 3 — DOM / page-content machine-learning model (PhiUSIIL HTML features)."""
import logging
from functools import lru_cache
from typing import Mapping, Optional

import joblib

from app.config import MODELS_DIR
from app.features.dom_features import DOM_FEATURE_NAMES, complete_dom_features, dom_matrix, explain_dom
from app.layers.base import LayerResult

log = logging.getLogger(__name__)
MODEL_PATH = MODELS_DIR / "dom_model.joblib"


@lru_cache(maxsize=1)
def load_model() -> Optional[dict]:
    if not MODEL_PATH.exists():
        log.warning("DOM model not found at %s — using rule-based fallback", MODEL_PATH)
        return None
    return joblib.load(MODEL_PATH)


def _rule_score(f: Mapping[str, float]) -> float:
    score = 5.0
    if f["HasPasswordField"]:
        score += 25 + 30 * f["HasExternalFormSubmit"] + 10 * f["HasHiddenFields"]
        score += 15 * (f["DomainTitleMatchScore"] < 10)
        score += 10 * (not f["HasCopyrightInfo"])
    score += 10 * (f["NoOfiFrame"] >= 3) + 10 * (f["NoOfSelfRef"] == 0 and f["NoOfExternalRef"] > 0)
    return min(100.0, score)


def analyze(url: str, title: str, raw_features: Mapping[str, float]) -> LayerResult:
    f = complete_dom_features(url, title, raw_features)
    reasons = explain_dom(f)
    bundle = load_model()
    if bundle is None:
        score, details = _rule_score(f), {"engine": "rules"}
    else:
        proba = bundle["model"].predict_proba(dom_matrix([f]))[0]
        score = float(proba[list(bundle["model"].classes_).index(1)] * 100)
        details = {"engine": "random-forest", "model_version": bundle.get("version", "unknown")}
    if score >= 50:
        reasons.insert(0, f"Page-structure classifier rates this {score:.0f}% likely phishing")
    elif not reasons:
        reasons.append("Page structure looks typical of legitimate sites")
    details["features"] = {k: round(f[k], 2) for k in DOM_FEATURE_NAMES}
    return LayerResult(name="dom_model", score=round(score, 2), reasons=reasons, details=details)
