"""Lexical URL feature extraction (Layer 2 input).

Features are computed from the URL string alone so they are available before the page
loads. The same function is used at training time (ml/) and at inference time.
"""
import math
import re
from collections import Counter
from typing import Dict, Iterable, List
from urllib.parse import unquote

import numpy as np

from app.config import get_config
from app.features.domain import normalize_url, parse_url

SUSPICIOUS_KEYWORDS = (
    "login", "log-in", "signin", "sign-in", "verify", "verification", "account", "update",
    "secure", "security", "banking", "confirm", "password", "credential", "wallet", "unlock",
    "suspend", "billing", "invoice", "support", "webscr", "authenticate", "recovery", "limited",
)
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id", "t.ly",
}
# Free hosting / site builders: legitimate platforms that are heavily abused for phishing.
FREE_HOSTING = {
    "000webhostapp.com", "weebly.com", "wixsite.com", "firebaseapp.com", "web.app",
    "github.io", "glitch.me", "netlify.app", "vercel.app", "pages.dev", "blogspot.com",
    "sites.google.com", "herokuapp.com", "repl.co", "ngrok.io", "ngrok-free.app",
    "workers.dev", "azurewebsites.net", "square.site", "godaddysites.com", "webflow.io",
}

FEATURE_NAMES: List[str] = [
    "url_length", "host_length", "path_length", "query_length", "num_dots", "num_hyphens",
    "num_underscores", "num_slashes", "num_digits", "digit_ratio", "letter_ratio",
    "special_ratio", "num_params", "num_subdomains", "has_ip", "has_at", "has_double_slash",
    "is_https", "has_port", "has_punycode", "has_non_ascii", "url_entropy", "host_entropy",
    "suspicious_tld", "keyword_hits", "is_shortener", "is_free_hosting", "hyphen_in_host",
    "longest_token", "pct_encoded", "has_exe_or_php", "tld_in_path", "char_continuation",
]


def _decode_idna(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna") if "xn--" in host else host
    except UnicodeError:
        return host


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _char_continuation_rate(text: str) -> float:
    """Longest runs of letters/digits/specials relative to length (as used by PhiUSIIL)."""
    if not text:
        return 0.0
    runs = {"a": 0, "d": 0, "s": 0}
    cur_kind, cur_len = None, 0
    for ch in text:
        kind = "a" if ch.isalpha() else "d" if ch.isdigit() else "s"
        cur_len = cur_len + 1 if kind == cur_kind else 1
        cur_kind = kind
        runs[kind] = max(runs[kind], cur_len)
    return sum(runs.values()) / len(text)


def extract_url_features(url: str) -> Dict[str, float]:
    p = parse_url(url)
    full = normalize_url(url)
    lower = full.lower()
    host = p.host
    n = max(len(full), 1)
    digits = sum(ch.isdigit() for ch in full)
    letters = sum(ch.isalpha() for ch in full)
    specials = n - digits - letters
    tokens = [t for t in re.split(r"[/.?=&\-_:]+", lower) if t]
    suspicious_tlds = set(get_config().get("suspicious_tlds", []))
    last_label = p.suffix.split(".")[-1] if p.suffix else ""
    registrable = p.registrable
    after_scheme = full.split("://", 1)[-1]

    return {
        "url_length": len(full),
        "host_length": len(host),
        "path_length": len(p.path),
        "query_length": len(p.query),
        "num_dots": full.count("."),
        "num_hyphens": full.count("-"),
        "num_underscores": full.count("_"),
        "num_slashes": full.count("/"),
        "num_digits": digits,
        "digit_ratio": digits / n,
        "letter_ratio": letters / n,
        "special_ratio": specials / n,
        "num_params": len([q for q in p.query.split("&") if q]),
        "num_subdomains": len([s for s in p.subdomain.split(".") if s and s != "www"]),
        "has_ip": float(p.is_ip or bool(re.search(r"\b0x[0-9a-f]{8}\b", host))),
        "has_at": float("@" in after_scheme),
        "has_double_slash": float("//" in after_scheme),
        "is_https": float(p.scheme == "https"),
        "has_port": float(bool(re.search(r":\d+$", after_scheme.split("/", 1)[0]))),
        "has_punycode": float("xn--" in host),
        "has_non_ascii": float(any(ord(ch) > 127 for ch in unquote(full))),
        "url_entropy": shannon_entropy(lower),
        "host_entropy": shannon_entropy(host),
        "suspicious_tld": float(last_label in suspicious_tlds),
        "keyword_hits": float(sum(k in lower for k in SUSPICIOUS_KEYWORDS)),
        "is_shortener": float(registrable in SHORTENERS),
        "is_free_hosting": float(registrable in FREE_HOSTING or host in FREE_HOSTING),
        "hyphen_in_host": float(_decode_idna(host).count("-")),
        "longest_token": float(max((len(t) for t in tokens), default=0)),
        "pct_encoded": float(full.count("%")),
        "has_exe_or_php": float(bool(re.search(r"\.(exe|scr|zip|php|cgi)(\?|$)", p.path.lower()))),
        "tld_in_path": float(bool(re.search(r"\.(com|net|org)[/.-]", (p.subdomain + p.path).lower()))),
        "char_continuation": _char_continuation_rate(after_scheme),
    }


def feature_matrix(urls: Iterable[str]) -> np.ndarray:
    """Vectorise URLs in FEATURE_NAMES order. Importable by sklearn pipelines."""
    rows = [extract_url_features(u) for u in urls]
    return np.array([[r[name] for name in FEATURE_NAMES] for r in rows], dtype=float)


def url_text(urls: Iterable[str]) -> List[str]:
    """Canonical string fed to the char n-gram vectoriser (scheme stripped, lower-cased)."""
    return [normalize_url(u).lower().split("://", 1)[-1] for u in urls]


def explain_url(features: Dict[str, float]) -> List[str]:
    """Human-readable reasons for the lexical signals that fired."""
    reasons = []
    if features["has_ip"]:
        reasons.append("Host is a raw IP address instead of a domain name")
    if features["has_at"]:
        reasons.append("URL contains '@', which hides the real destination host")
    if features["has_punycode"] or features["has_non_ascii"]:
        reasons.append("Internationalised (punycode) host — possible homoglyph attack")
    if features["suspicious_tld"]:
        reasons.append("Top-level domain is frequently abused for phishing")
    if features["keyword_hits"] >= 2:
        reasons.append(f"Contains {int(features['keyword_hits'])} credential-lure keywords (login, verify, secure…)")
    if features["num_subdomains"] >= 3:
        reasons.append(f"Deeply nested subdomains ({int(features['num_subdomains'])} levels)")
    if features["url_length"] > 100:
        reasons.append(f"Unusually long URL ({int(features['url_length'])} characters)")
    if features["is_shortener"]:
        reasons.append("URL shortener hides the final destination")
    if features["is_free_hosting"]:
        reasons.append("Hosted on a free hosting / site-builder platform commonly abused by phishers")
    if features["hyphen_in_host"] >= 2:
        reasons.append("Multiple hyphens in the host name")
    if features["tld_in_path"]:
        reasons.append("A '.com'-style domain appears inside the subdomain or path (domain spoofing)")
    if features["has_port"]:
        reasons.append("Non-standard port specified in URL")
    if not features["is_https"]:
        reasons.append("Connection is not encrypted (HTTP)")
    return reasons
