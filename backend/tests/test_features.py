from app.features.dom_features import complete_dom_features, title_match_score
from app.features.domain import parse_url
from app.features.url_features import FEATURE_NAMES, extract_url_features, feature_matrix


def test_parse_url_handles_missing_scheme_and_suffixes():
    p = parse_url("login.paypal.co.uk/x")
    assert p.registrable == "paypal.co.uk"
    assert p.subdomain == "login"
    assert p.scheme == "http"


def test_ip_host_detected():
    f = extract_url_features("http://192.168.10.5/bank/login.php")
    assert f["has_ip"] == 1 and f["is_https"] == 0 and f["has_exe_or_php"] == 1


def test_lure_signals():
    f = extract_url_features("https://paypal.com.secure-verify.xyz/login/confirm@evil")
    assert f["suspicious_tld"] == 1
    assert f["tld_in_path"] == 1
    assert f["has_at"] == 1
    assert f["keyword_hits"] >= 3


def test_punycode_not_counted_as_hyphens():
    f = extract_url_features("https://xn--pypal-4ve.com/")
    assert f["has_punycode"] == 1 and f["hyphen_in_host"] == 0


def test_feature_matrix_shape():
    assert feature_matrix(["a.com", "b.org/x"]).shape == (2, len(FEATURE_NAMES))


def test_title_match():
    assert title_match_score("github", "GitHub: Let's build from here") == 100
    assert title_match_score("secure-acct-77", "Sign in to your PayPal account") < 10
    f = complete_dom_features("https://github.com/login", "Sign in to GitHub", {"HasPasswordField": 1})
    assert f["HasTitle"] == 1 and f["DomainTitleMatchScore"] == 100 and f["NoOfiFrame"] == 0
