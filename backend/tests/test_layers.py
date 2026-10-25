from app.layers import brand, reputation
from app.layers.base import LayerResult
from app.policy import ALLOW, BLOCK, RESTRICT, WARN, decide


def test_brand_homoglyph_typosquat_combosquat():
    assert brand.analyze("https://xn--pypal-4ve.com/").score >= 95          # Cyrillic 'а'
    assert brand.analyze("https://paypa1.com/login").score >= 85            # leetspeak
    assert brand.analyze("https://amazonn.com/").score >= 85                # typo
    assert brand.analyze("https://netflix-billing-update.com/").score >= 60 # combosquat
    r = brand.analyze("https://secure-portal.net/", title="Netflix", text="Sign in to Netflix",
                      has_password=True)
    assert r.score == 80 and r.details["impersonated_brand"] == "Netflix"


def test_brand_official_domains_are_clean():
    for url in ("https://www.paypal.com/signin", "https://login.microsoftonline.com/",
                "https://accounts.google.com/"):
        r = brand.analyze(url, title="Sign in", has_password=True)
        assert r.score == 0 and "verified_brand" in r.details


def test_reputation_allow_and_free_hosting():
    assert reputation.analyze("https://github.com/x", network=False).details.get("allowlisted")
    r = reputation.analyze("https://login-portal.web.app/", network=False)
    assert not r.details.get("allowlisted") and r.score >= 30


def test_policy_thresholds():
    def L(name, score, **details):
        return LayerResult(name, score, details=details)

    assert decide([L("reputation", 0, allowlisted=True), L("url_model", 2), L("brand", 0)]).verdict == ALLOW
    assert decide([L("reputation", 15), L("url_model", 55), L("brand", 30)]).verdict == WARN
    assert decide([L("reputation", 15), L("url_model", 68), L("brand", 60)],
                  has_credential_form=True).verdict == RESTRICT
    assert decide([L("reputation", 100, blocklisted=True), L("url_model", 0)]).verdict == BLOCK
    # escalation: a decisive single layer is not averaged away
    assert decide([L("reputation", 15), L("url_model", 5), L("brand", 95)]).verdict == BLOCK
    # ...but a lone ML layer is never enough to block
    assert decide([L("reputation", 15), L("url_model", 2), L("dom_model", 100), L("brand", 0)]).verdict == WARN
    # ...unless another layer supplies real supporting evidence
    assert decide([L("reputation", 35), L("url_model", 95), L("brand", 0)]).verdict == BLOCK
    # a single strong layer always earns at least a warning
    assert decide([L("reputation", 5), L("url_model", 3), L("brand", 85)]).verdict == WARN
    # corroboration: two strong independent layers
    d = decide([L("reputation", 15), L("url_model", 77), L("brand", 75)])
    assert d.verdict == BLOCK and d.risk >= 82


def test_unavailable_layer_is_excluded_from_weights():
    d = decide([LayerResult("url_model", 40), LayerResult("dom_model", None)])
    dom = next(l for l in d.layers if l["name"] == "dom_model")
    assert dom["weight"] == 0 and d.risk == 40
