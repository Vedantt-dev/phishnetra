"""Generate the small synthetic seed datasets bundled in backend/data/.

These let PhishNetra train working models without any downloads. They are NOT a
substitute for real data: for evaluation numbers in the report, train on PhiUSIIL
(see download_datasets.py). Output is deterministic (fixed RNG seed).
"""
import csv
import random

from common import SEED_DIR

rng = random.Random(1337)

WORDS = ("cloud green river tech north blue data smart craft home city open bright fresh pixel "
         "global urban media health travel learn code market star solar maple ocean stone forge "
         "nova alpha prime metro civic garden harbor summit atlas quantum vertex lumen orbit").split()
LEGIT_TLDS = ["com"] * 8 + ["org", "net", "io", "in", "co.uk", "de", "edu", "gov", "co"]
SUS_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "click", "link", "work", "icu", "buzz", "live", "info", "online", "site"]
BRANDS = ["paypal", "apple", "microsoft", "netflix", "amazon", "google", "facebook", "instagram", "chase",
          "wellsfargo", "dhl", "fedex", "coinbase", "binance", "metamask", "outlook", "office365", "icloud",
          "hdfc", "icici", "paytm", "sbi", "linkedin", "dropbox", "docusign", "adobe", "usps", "steam", "ebay"]
LURES = ["login", "signin", "verify", "secure", "account", "update", "confirm", "billing", "unlock",
         "support", "recovery", "auth", "wallet", "session", "validate", "suspended", "webscr"]
FREEHOST = ["000webhostapp.com", "weebly.com", "wixsite.com", "firebaseapp.com", "web.app", "github.io",
            "glitch.me", "netlify.app", "vercel.app", "pages.dev", "herokuapp.com", "workers.dev"]
TOP_SITES = [l.strip() for l in (SEED_DIR / "allowlist_seed.txt").read_text().splitlines()
             if l.strip() and not l.startswith("#")]
LEGIT_LOGINS = [
    "https://accounts.google.com/signin/v2/identifier", "https://login.microsoftonline.com/common/oauth2/authorize",
    "https://www.paypal.com/signin", "https://appleid.apple.com/sign-in", "https://www.amazon.com/ap/signin",
    "https://www.facebook.com/login/", "https://github.com/login", "https://www.linkedin.com/login",
    "https://secure.chase.com/web/auth/dashboard", "https://login.live.com/login.srf",
    "https://www.netflix.com/login", "https://www.dropbox.com/login", "https://netbanking.hdfcbank.com/netbanking/",
]


def w():
    return rng.choice(WORDS)


def slug(n=3):
    return "-".join(w() for _ in range(n))


def hexs(n):
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def typo(brand):
    ops = [
        lambda b: b.replace("l", "1", 1) if "l" in b else b + "1",
        lambda b: b.replace("o", "0", 1) if "o" in b else b + "0",
        lambda b: b[:-1] if len(b) > 4 else b + "s",
        lambda b: b + b[-1],
        lambda b: b.replace("m", "rn", 1) if "m" in b else b + "-online",
        lambda b: b[: len(b) // 2] + b[len(b) // 2 + 1:] if len(b) > 5 else b + "x",
    ]
    return rng.choice(ops)(brand)


def legit_url():
    kind = rng.random()
    if kind < 0.35:
        domain = rng.choice(TOP_SITES)
    else:
        domain = f"{w()}{rng.choice(['', '-'])}{w()}.{rng.choice(LEGIT_TLDS)}"
    sub = rng.choice(["www.", "www.", "", "blog.", "shop.", "docs.", "app.", "news."])
    path = rng.choice([
        "/", "", "/about", "/contact", f"/blog/{slug()}", f"/news/{rng.randint(2015, 2026)}/{slug(4)}",
        f"/products/{rng.randint(100, 99999)}", f"/search?q={w()}+{w()}", f"/docs/{w()}/{slug(2)}",
        f"/category/{w()}?page={rng.randint(1, 30)}", f"/{w()}/{w()}.html", f"/user/{w()}{rng.randint(1, 999)}",
        "/login", "/account/settings", f"/watch?v={hexs(11)}",
    ])
    scheme = "https" if rng.random() < 0.93 else "http"
    if kind > 0.97:
        return rng.choice(LEGIT_LOGINS)
    return f"{scheme}://{sub}{domain}{path}"


def phish_url():
    b, lure = rng.choice(BRANDS), rng.choice(LURES)
    scheme = "https" if rng.random() < 0.55 else "http"
    templates = [
        lambda: f"{scheme}://{typo(b)}.{rng.choice(['com', 'net'] + SUS_TLDS)}/{lure}",
        lambda: f"{scheme}://{b}-{lure}-{rng.choice(LURES)}.{rng.choice(SUS_TLDS)}/{lure}/{rng.choice(['index', 'login', 'verify'])}.php",
        lambda: f"http://{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}/{b}/{lure}.php?cmd={lure}&id={hexs(16)}",
        lambda: f"{scheme}://{b}.com.{lure}-{hexs(6)}.{rng.choice(SUS_TLDS + ['com'])}/{lure}",
        lambda: f"https://{w()}{hexs(4)}.{rng.choice(FREEHOST)}/{b}/{lure}.html",
        lambda: f"{scheme}://{w()}{w()}.{rng.choice(LEGIT_TLDS)}/wp-content/{rng.choice(['uploads', 'plugins', 'themes'])}/{hexs(8)}/{b}/{lure}/index.php",
        lambda: f"https://{lure}-{b}-{rng.choice(LURES)}.com/{lure}?session={hexs(32)}&{rng.choice(LURES)}=true",
        lambda: f"https://{b}.{lure}@{w()}{hexs(3)}.{rng.choice(SUS_TLDS)}/",
        lambda: f"https://{hexs(rng.randint(10, 24))}.{w()}-{lure}.{rng.choice(SUS_TLDS)}/{b}/",
        lambda: f"{scheme}://{lure}.{b}.{lure}-{rng.choice(LURES)}.{w()}{hexs(2)}.{rng.choice(SUS_TLDS)}/{lure}",
        lambda: f"https://{rng.choice(['bit.ly', 'tinyurl.com', 'cutt.ly', 'rb.gy'])}/{hexs(7)}",
        lambda: f"https://www.{b}{rng.choice(['-', ''])}{rng.choice(['support', 'help', 'service', 'online', 'secure'])}.{rng.choice(['com', 'net', 'org', 'info', 'online'])}/{lure}/{rng.choice(LURES)}",
    ]
    return rng.choice(templates)()


def write_urls(n_per_class=3000):
    seen, rows = set(), []
    for label, gen in ((0, legit_url), (1, phish_url)):
        count = 0
        while count < n_per_class:
            url = gen()
            if url in seen:
                continue
            seen.add(url)
            rows.append((url, label))
            count += 1
    rng.shuffle(rows)
    with open(SEED_DIR / "seed_urls.csv", "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "phishing"])
        writer.writerows(rows)
    return len(rows)


def dom_row(phish: bool):
    """Overlapping distributions: page size alone must not separate the classes (small
    honest pages and large cloned phishing pages both exist). Credential-harvesting
    structure is what should carry the signal."""
    p = rng.random
    small = p() < (0.6 if phish else 0.35)
    loc = int(rng.lognormvariate(4.6, 0.9) if small else rng.lognormvariate(6.8, 1.0))
    longest = int(rng.lognormvariate(5.5 if small else 7.5, 1.3))
    if phish:
        has_pw = p() < 0.75
        return {
            "LineOfCode": loc, "LargestLineLength": longest,
            "HasTitle": int(p() < 0.9), "DomainTitleMatchScore": 0 if p() < 0.85 else rng.randint(10, 100),
            "URLTitleMatchScore": 0 if p() < 0.8 else rng.randint(5, 60),
            "HasFavicon": int(p() < 0.4), "IsResponsive": int(p() < 0.55), "HasDescription": int(p() < 0.25),
            "NoOfPopup": int(p() < 0.15), "NoOfiFrame": rng.choice([0, 0, 0, 1, 2, 4]),
            "HasExternalFormSubmit": int(has_pw and p() < 0.55), "HasSocialNet": int(p() < 0.2),
            "HasSubmitButton": int(has_pw or p() < 0.3), "HasHiddenFields": int(p() < 0.55),
            "HasPasswordField": int(has_pw), "Bank": int(p() < 0.3), "Pay": int(p() < 0.4),
            "Crypto": int(p() < 0.12), "HasCopyrightInfo": int(p() < 0.35),
            "NoOfImage": rng.randint(0, 6 if small else 40), "NoOfCSS": rng.randint(0, 3 if small else 15),
            "NoOfJS": rng.randint(0, 5 if small else 30),
            "NoOfSelfRef": rng.choice([0, 0, 0, 1, 2, 4]) if small else rng.randint(0, 40),
            "NoOfEmptyRef": rng.randint(2, 15), "NoOfExternalRef": rng.randint(0, 15), "phishing": 1,
        }
    has_pw = p() < 0.15
    return {
        "LineOfCode": loc, "LargestLineLength": longest,
        "HasTitle": int(p() < 0.98), "DomainTitleMatchScore": rng.randint(30, 100) if p() < 0.7 else 0,
        "URLTitleMatchScore": rng.randint(10, 80) if p() < 0.55 else 0,
        "HasFavicon": int(p() < 0.75), "IsResponsive": int(p() < 0.85), "HasDescription": int(p() < 0.7),
        "NoOfPopup": int(p() < 0.05), "NoOfiFrame": rng.choice([0, 0, 0, 1, 1, 2, 3, 5]),
        "HasExternalFormSubmit": int(p() < 0.08), "HasSocialNet": int(p() < 0.5),
        "HasSubmitButton": int(p() < 0.5), "HasHiddenFields": int(p() < 0.45), "HasPasswordField": int(has_pw),
        "Bank": int(p() < 0.1), "Pay": int(p() < 0.25), "Crypto": int(p() < 0.05), "HasCopyrightInfo": int(p() < 0.75),
        "NoOfImage": rng.randint(0, 10 if small else 120), "NoOfCSS": rng.randint(0, 4 if small else 30),
        "NoOfJS": rng.randint(0, 6 if small else 60),
        "NoOfSelfRef": rng.randint(1, 15) if small else rng.randint(10, 300),
        "NoOfEmptyRef": rng.randint(0, 5), "NoOfExternalRef": rng.randint(0, 8 if small else 120), "phishing": 0,
    }


def write_dom(n_per_class=3000):
    rows = [dom_row(False) for _ in range(n_per_class)] + [dom_row(True) for _ in range(n_per_class)]
    rng.shuffle(rows)
    with open(SEED_DIR / "seed_dom.csv", "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


if __name__ == "__main__":
    print("seed_urls.csv rows:", write_urls())
    print("seed_dom.csv rows:", write_dom())
