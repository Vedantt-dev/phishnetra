from fastapi.testclient import TestClient

from app.main import app


def test_end_to_end_scan_flow():
    with TestClient(app) as client:
        assert client.get("/health").json()["status"] == "ok"

        ok = client.post("/api/v1/scan", json={"url": "https://www.google.com/"}).json()
        assert ok["verdict"] == "ALLOW" and ok["trust"] == "verified"

        bad = client.post("/api/v1/scan", json={"url": "http://paypa1-secure-login.xyz/verify/account"}).json()
        assert bad["verdict"] in ("WARN", "BLOCK") and bad["risk"] >= 30
        assert {l["name"] for l in bad["layers"]} == {"reputation", "url_model", "dom_model", "brand"}
        assert bad["reasons"]

        again = client.post("/api/v1/scan", json={"url": "http://paypa1-secure-login.xyz/verify/account"}).json()
        assert again["cached"] is True

        dom = client.post("/api/v1/scan/dom", json={
            "url": "https://secure-acct-check.top/signin", "title": "PayPal: Log in",
            "text": "Log in to your PayPal account", "features": {
                "HasPasswordField": 1, "HasExternalFormSubmit": 1, "HasHiddenFields": 1,
                "LineOfCode": 120, "NoOfSelfRef": 0, "NoOfExternalRef": 3, "NoOfEmptyRef": 9},
        }).json()
        assert dom["verdict"] in ("RESTRICT", "BLOCK") and dom["impersonated_brand"] == "PayPal"

        assert client.post("/api/v1/override", json={"scan_id": dom["scan_id"]}).json()["ok"]
        assert client.post("/api/v1/feedback", json={"url": "http://evil-test-domain.top/x", "label": "phishing"}).json()["ok"]
        blocked = client.post("/api/v1/scan", json={"url": "http://evil-test-domain.top/other"}).json()
        assert blocked["verdict"] == "BLOCK"

        stats = client.get("/api/v1/stats").json()
        assert stats["total_scans"] >= 4 and stats["overrides"] == 1
        assert len(client.get("/api/v1/scans?limit=10").json()) >= 4
        assert "evil-test-domain.top" in client.get("/api/v1/blocklist").json()["domains"]
