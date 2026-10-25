"""Layer 4 — Brand impersonation & visual similarity.

Detects typosquatting, homoglyph/IDN spoofing and combosquatting against a catalogue of
frequently-phished brands, brand claims in page content served from a foreign domain, and
(optionally) favicon perceptual-hash matches against official brand favicons.
"""
import io
import json
import logging
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from typing import List, Optional, Tuple

import httpx
from rapidfuzz.distance import Levenshtein

from app.config import DATA_DIR, OFFLINE
from app.features.domain import ParsedURL, parse_url
from app.layers.base import LayerResult
from app.layers.reputation import intel

log = logging.getLogger(__name__)

# Visually confusable characters → ASCII skeleton (subset of Unicode TR39 confusables).
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ӏ": "l", "ԁ": "d", "ɡ": "g", "ѕ": "s", "һ": "h", "ո": "n", "ν": "v", "ο": "o", "α": "a",
    "ε": "e", "κ": "k", "ρ": "p", "τ": "t", "υ": "u", "ı": "i", "ȷ": "j",
}
LEET = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "$": "s", "@": "a"}
MULTI = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("ii", "u"))


@dataclass(frozen=True)
class Brand:
    name: str
    domains: Tuple[str, ...]
    keywords: Tuple[str, ...]

    def owns(self, p: ParsedURL) -> bool:
        return any(p.registrable == d or p.host == d or p.host.endswith("." + d) for d in self.domains)


@lru_cache(maxsize=1)
def brands() -> List[Brand]:
    raw = json.loads((DATA_DIR / "brands.json").read_text())
    return [Brand(b["name"], tuple(b["domains"]), tuple(b["keywords"])) for b in raw]


@lru_cache(maxsize=1)
def favicon_hashes() -> dict:
    path = DATA_DIR / "brand_favicon_hashes.json"
    return json.loads(path.read_text()) if path.exists() else {}


def decode_host(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna") if "xn--" in host else host
    except UnicodeError:
        return host


def skeleton(label: str) -> str:
    """Collapse homoglyphs, leetspeak and diacritics so 'pаypa1' and 'paypal' compare equal."""
    label = "".join(CONFUSABLES.get(ch, ch) for ch in label.lower())
    label = unicodedata.normalize("NFKD", label).encode("ascii", "ignore").decode()
    label = "".join(LEET.get(ch, ch) for ch in label)
    for src, dst in MULTI:
        label = label.replace(src, dst)
    return label


def _url_signals(p: ParsedURL) -> Tuple[float, List[str], Optional[str]]:
    best, reasons, target = 0.0, [], None
    unicode_sld = decode_host(p.sld)
    sld_skel = skeleton(unicode_sld)
    tokens = [t for t in re.split(r"[.\-]", decode_host(p.host)) if t]
    path_lower = (p.path + "?" + p.query).lower()

    def bump(score: float, reason: str, brand: Brand) -> None:
        nonlocal best, target
        if score > best:
            best, target = score, brand.name
        reasons.append(reason)

    for brand in brands():
        if brand.owns(p):
            continue
        for kw in brand.keywords:
            if sld_skel == kw and unicode_sld != kw:
                bump(95, f"Homoglyph spoof of {brand.name}: '{unicode_sld}' imitates '{kw}'", brand)
            elif len(kw) >= 5 and 0 < Levenshtein.distance(unicode_sld, kw) <= (1 if len(kw) < 8 else 2):
                bump(85, f"Typosquat of {brand.name}: '{p.sld}' is one keystroke from '{kw}'", brand)
            elif any(t == kw or skeleton(t) == kw for t in tokens):
                bump(75, f"Uses the {brand.name} name in a domain {brand.name} does not own ({p.host})", brand)
            elif len(kw) >= 5 and any(kw in skeleton(t) for t in tokens):
                bump(60, f"Domain embeds '{kw}' (combosquatting {brand.name})", brand)
            elif len(kw) >= 5 and kw in path_lower:
                bump(40, f"URL path references {brand.name} on an unrelated domain", brand)
    return best, reasons, target


def _content_signals(p: ParsedURL, title: str, text: str, has_password: bool):
    haystack = f"{title} {text[:4000]}".lower()
    for brand in brands():
        if brand.owns(p):
            continue
        names = {brand.name.lower(), *brand.keywords}
        if any(re.search(rf"\b{re.escape(n)}\b", haystack) for n in names if len(n) >= 4):
            if has_password:
                return 80.0, [f"Login page claims to be {brand.name} but is not on a {brand.name} domain"], brand.name
            if any(n in title.lower() for n in names):
                return 30.0, [f"Page title mentions {brand.name} on a third-party domain"], brand.name
    return 0.0, [], None


def _favicon_signal(p: ParsedURL, favicon_url: Optional[str]):
    hashes = favicon_hashes()
    if not favicon_url or not hashes or OFFLINE or favicon_url.startswith("data:"):
        return 0.0, [], None
    try:
        import imagehash
        from PIL import Image

        resp = httpx.get(favicon_url, timeout=3, follow_redirects=True)
        resp.raise_for_status()
        h = imagehash.phash(Image.open(io.BytesIO(resp.content)).convert("RGBA"))
    except Exception:  # noqa: BLE001 — broken favicons are common and not a signal
        return 0.0, [], None
    for brand in brands():
        if brand.owns(p) or brand.name not in hashes:
            continue
        distance = min(h - imagehash.hex_to_hash(ref) for ref in hashes[brand.name])
        if distance <= 6:
            return 90.0, [f"Favicon is visually identical to {brand.name}'s (pHash distance {distance})"], brand.name
    return 0.0, [], None


def analyze(url: str, title: str = "", text: str = "", has_password: bool = False,
            favicon_url: Optional[str] = None) -> LayerResult:
    p = parse_url(url)
    result = LayerResult(name="brand", score=0.0)
    owner = next((b for b in brands() if b.owns(p)), None)
    if owner:
        result.details["verified_brand"] = owner.name
        result.reasons.append(f"Official {owner.name} domain")
        return result
    if intel.is_allowlisted(p):
        result.reasons.append("Allowlisted domain — no impersonation checks needed")
        return result

    signals = [_url_signals(p)]
    if title or text:
        signals.append(_content_signals(p, title, text, has_password))
    signals.append(_favicon_signal(p, favicon_url))

    score, target = 0.0, None
    for s, reasons, brand_name in signals:
        result.reasons.extend(reasons)
        if s > score:
            score, target = s, brand_name
    result.score = score
    if target:
        result.details["impersonated_brand"] = target
    if not result.reasons:
        result.reasons.append("No brand impersonation detected")
    return result
