"""DOM / page-content features (Layer 3 input).

Column names follow the PhiUSIIL Phishing URL Dataset (UCI, 2024) HTML features so the
model can be trained on that dataset and served from features the extension's content
script extracts from the live page.
"""
import re
from typing import Dict, Iterable, List, Mapping

import numpy as np

from app.features.domain import normalize_url, parse_url

DOM_FEATURE_NAMES: List[str] = [
    "LineOfCode", "LargestLineLength", "HasTitle", "DomainTitleMatchScore",
    "URLTitleMatchScore", "HasFavicon", "IsResponsive", "HasDescription", "NoOfPopup",
    "NoOfiFrame", "HasExternalFormSubmit", "HasSocialNet", "HasSubmitButton",
    "HasHiddenFields", "HasPasswordField", "Bank", "Pay", "Crypto", "HasCopyrightInfo",
    "NoOfImage", "NoOfCSS", "NoOfJS", "NoOfSelfRef", "NoOfEmptyRef", "NoOfExternalRef",
]

# Features the browser computes server-side from title + URL rather than in the page.
DERIVED = {"DomainTitleMatchScore", "URLTitleMatchScore", "HasTitle"}


def _title_tokens(title: str) -> List[str]:
    return [t for t in re.findall(r"[a-z0-9]+", title.lower()) if len(t) >= 3]


def title_match_score(target: str, title: str) -> float:
    """0-100: share of the target string covered by words taken from the page title."""
    target = re.sub(r"[^a-z0-9]", "", target.lower())
    if not target or not title:
        return 0.0
    covered = sum(len(tok) for tok in set(_title_tokens(title)) if tok in target)
    return float(min(100.0, 100.0 * covered / len(target)))


def complete_dom_features(url: str, title: str, raw: Mapping[str, float]) -> Dict[str, float]:
    """Fill derived columns and default anything the client did not send to 0."""
    p = parse_url(url)
    feats = {name: float(raw.get(name, 0) or 0) for name in DOM_FEATURE_NAMES}
    feats["HasTitle"] = float(bool(title and title.strip()))
    feats["DomainTitleMatchScore"] = title_match_score(p.sld or p.host, title)
    feats["URLTitleMatchScore"] = title_match_score(normalize_url(url).split("://", 1)[-1], title)
    return feats


def dom_matrix(rows: Iterable[Mapping[str, float]]) -> np.ndarray:
    return np.array([[float(r.get(n, 0) or 0) for n in DOM_FEATURE_NAMES] for r in rows], dtype=float)


def explain_dom(f: Mapping[str, float]) -> List[str]:
    reasons = []
    if f["HasPasswordField"] and f["HasExternalFormSubmit"]:
        reasons.append("Password form submits credentials to a different domain")
    elif f["HasPasswordField"]:
        reasons.append("Page requests a password")
    if f["HasHiddenFields"] and f["HasPasswordField"]:
        reasons.append("Credential form contains hidden fields")
    if f["NoOfiFrame"] >= 3:
        reasons.append(f"Page embeds {int(f['NoOfiFrame'])} iframes")
    if f["NoOfPopup"] >= 1:
        reasons.append("Page script opens pop-up windows")
    if f["HasTitle"] and f["DomainTitleMatchScore"] < 10 and f["HasPasswordField"]:
        reasons.append("Page title does not match the domain it is served from")
    if f["NoOfExternalRef"] > 0 and f["NoOfSelfRef"] == 0:
        reasons.append("All links point to other domains (cloned page pattern)")
    if f["NoOfEmptyRef"] >= 5:
        reasons.append(f"{int(f['NoOfEmptyRef'])} dead '#' links (typical of cloned login pages)")
    if not f["HasCopyrightInfo"] and not f["HasDescription"] and f["HasPasswordField"]:
        reasons.append("Login page lacks copyright and meta description")
    if f["Bank"] or f["Pay"] or f["Crypto"]:
        reasons.append("Page content references banking, payments or crypto")
    return reasons
