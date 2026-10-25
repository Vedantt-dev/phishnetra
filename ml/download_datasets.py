"""Download the public datasets used for training and evaluation.

    python ml/download_datasets.py --phiusiil    # UCI PhiUSIIL Phishing URL Dataset (~55 MB CSV)
    python ml/download_datasets.py --tranco      # Tranco top-1M → backend/data/allowlist.txt (top 10k)
    python ml/download_datasets.py --openphish   # OpenPhish community feed → backend/data/openphish_feed.txt

PhiUSIIL: A. Prasad & S. Chandra, "PhiUSIIL: A diverse security profile empowered phishing
URL detection framework based on similarity index and incremental learning",
Computers & Security, 2024. Licence: CC BY 4.0. https://doi.org/10.24432/C5Q90K
"""
import argparse
import csv
import io
import zipfile

import httpx

from common import DATASETS_DIR, PHIUSIIL_CSV, SEED_DIR

PHIUSIIL_ZIP = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
TRANCO_ZIP = "https://tranco-list.eu/top-1m.csv.zip"
OPENPHISH = "https://openphish.com/feed.txt"


def fetch(url: str) -> bytes:
    print("downloading", url)
    with httpx.stream("GET", url, follow_redirects=True, timeout=120) as resp:
        resp.raise_for_status()
        buf = io.BytesIO()
        for chunk in resp.iter_bytes():
            buf.write(chunk)
    print(f"  {buf.tell() / 1e6:.1f} MB")
    return buf.getvalue()


def phiusiil():
    DATASETS_DIR.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(fetch(PHIUSIIL_ZIP))) as zf:
        member = next(n for n in zf.namelist() if n.endswith(".csv"))
        PHIUSIIL_CSV.write_bytes(zf.read(member))
    print("wrote", PHIUSIIL_CSV)


def tranco(top: int = 10_000):
    with zipfile.ZipFile(io.BytesIO(fetch(TRANCO_ZIP))) as zf:
        rows = csv.reader(io.TextIOWrapper(zf.open(zf.namelist()[0])))
        domains = [r[1] for _, r in zip(range(top), rows)]
    out = SEED_DIR / "allowlist.txt"
    out.write_text("# Tranco top-%d (https://tranco-list.eu)\n" % top + "\n".join(domains) + "\n")
    print("wrote", out, len(domains), "domains")


def openphish():
    out = SEED_DIR / "openphish_feed.txt"
    out.write_bytes(fetch(OPENPHISH))
    print("wrote", out)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--phiusiil", action="store_true")
    ap.add_argument("--tranco", action="store_true")
    ap.add_argument("--openphish", action="store_true")
    args = ap.parse_args()
    if not (args.phiusiil or args.tranco or args.openphish):
        ap.error("choose at least one of --phiusiil --tranco --openphish")
    if args.phiusiil:
        phiusiil()
    if args.tranco:
        tranco()
    if args.openphish:
        openphish()
