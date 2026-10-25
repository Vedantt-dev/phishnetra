"""Zero-Trust Policy Engine.

Never trust, always verify: every navigation is scored by all available layers, the
scores are fused into a single explainable risk value, and the decision is mapped to a
browser enforcement action. Trust is never permanent — verdicts expire after a TTL.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from app.config import get_config
from app.layers.base import LayerResult

ALLOW, WARN, RESTRICT, BLOCK = "ALLOW", "WARN", "RESTRICT", "BLOCK"


@dataclass
class Decision:
    risk: float
    verdict: str
    trust: str                       # verified | unverified | suspicious | malicious
    layers: List[Dict] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    impersonated_brand: Optional[str] = None


def fuse(layers: List[LayerResult]) -> Dict[str, Dict]:
    """Weighted average over the layers that produced a score, with contributions."""
    weights = get_config()["weights"]
    active = [l for l in layers if l.available]
    total_w = sum(weights.get(l.name, 0) for l in active) or 1.0
    out = {}
    for l in layers:
        w = weights.get(l.name, 0) / total_w if l.available else 0.0
        out[l.name] = {
            "name": l.name,
            "score": l.score,
            "weight": round(w, 3),
            "contribution": round((l.score or 0) * w, 2),
            "available": l.available,
            "reasons": l.reasons,
            "details": l.details,
        }
    return out


def decide(layers: List[LayerResult], has_credential_form: bool = False) -> Decision:
    cfg = get_config()
    th = cfg["thresholds"]
    fused = fuse(layers)
    by_name = {l.name: l for l in layers}
    risk = sum(v["contribution"] for v in fused.values())

    # A decisive signal from one layer must not be averaged away by the others.
    top = max((l for l in layers if l.available), key=lambda l: l.score, default=None)
    decisive = [l for l in layers if l.available and l.name in cfg["escalation_layers"]]
    top_decisive = max(decisive, key=lambda l: l.score, default=None)
    if top_decisive is not None and top_decisive.score >= cfg["escalation_floor"]:
        risk = max(risk, top_decisive.score)
    if top is not None and top.score >= cfg["single_layer_warn"]:
        risk = max(risk, th["warn"] + (top.score - cfg["single_layer_warn"]))
    corr = cfg["corroboration"]
    strong = sorted((l.score for l in layers if l.available and l.score >= corr["min_layer_score"]), reverse=True)
    supporting = [l for l in layers if l.available and l.score >= corr["support_score"]]
    if strong and len(supporting) >= 2:
        risk = max(risk, strong[0] + corr["bonus"] * (len(strong) - 1))

    rep = by_name.get("reputation")
    brand = by_name.get("brand")
    blocklisted = bool(rep and rep.details.get("blocklisted"))
    verified = bool(rep and rep.details.get("allowlisted")) or bool(brand and brand.details.get("verified_brand"))
    if verified and risk < th["warn"]:
        risk = min(risk, 10.0)

    risk = round(min(100.0, max(0.0, risk)), 1)

    if blocklisted or risk >= th["block"]:
        verdict, trust = BLOCK, "malicious"
    elif has_credential_form and not verified and risk >= th["restrict"]:
        verdict, trust = RESTRICT, "suspicious"
    elif risk >= th["warn"]:
        verdict, trust = WARN, "suspicious"
    else:
        verdict, trust = ALLOW, "verified" if verified else "unverified"

    # Surface the reasons of the layers that drove the decision first.
    ranked = sorted(fused.values(), key=lambda v: v["contribution"], reverse=True)
    reasons: List[str] = []
    for layer in ranked:
        if not layer["available"]:
            continue
        for r in layer["reasons"]:
            if r not in reasons:
                reasons.append(r)
    impersonated = brand.details.get("impersonated_brand") if brand else None
    return Decision(risk=risk, verdict=verdict, trust=trust, layers=list(fused.values()),
                    reasons=reasons[:8], impersonated_brand=impersonated)
