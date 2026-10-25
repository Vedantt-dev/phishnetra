"""Domain parsing helpers shared by every layer."""
import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlsplit

import tldextract

# Use the bundled public-suffix snapshot only: never fetch or cache it (read-only serverless FS).
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


@dataclass(frozen=True)
class ParsedURL:
    url: str
    scheme: str
    host: str
    subdomain: str
    sld: str            # second-level label, e.g. "paypal"
    suffix: str         # public suffix, e.g. "co.uk"
    registrable: str    # sld + suffix, e.g. "paypal.co.uk"
    path: str
    query: str
    is_ip: bool


def normalize_url(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    return url


@lru_cache(maxsize=4096)
def parse_url(url: str) -> ParsedURL:
    url = normalize_url(url)
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    ext = _extract(host)
    registrable = host if is_ip else (f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain)
    return ParsedURL(
        url=url,
        scheme=parts.scheme.lower(),
        host=host,
        subdomain="" if is_ip else ext.subdomain,
        sld="" if is_ip else ext.domain,
        suffix="" if is_ip else ext.suffix,
        registrable=registrable,
        path=parts.path or "/",
        query=parts.query,
        is_ip=is_ip,
    )
