"""Infrastructure Investigator history: finished investigations are saved, listed, reopened, diffed and deleted."""
import time
from unittest import mock

import pytest

from core import investigations as hist


def fake_result(seed, domains, mode="malicious"):
    return {"seed": seed, "seed_root": seed, "depth": 2, "keywords": [],
            "nodes": [{"id": f"domain:{d}", "type": "domain", "label": d, "data": {}} for d, _ in domains], "edges": [],
            "domains": [{"domain": d, "link_confidence": c, "favicon": None, "dns": {"a": ["203.0.113.7"], "aaaa": [], "mx": [], "ns": []}, "artifacts": {}} for d, c in domains],
            "actor": {"mode": mode, "confidence": "high", "sophistication": 42, "summary": "test"},
            "stats": {"domains_profiled": len(domains), "nodes": len(domains), "edges": 0, "linked_high": sum(c == "high" for _, c in domains),
                      "linked_medium": 0, "linked_low": 0, "elapsed_sec": 1.0},
            "sources": [], "errors": []}


@pytest.fixture
def client(isolated_store):
    from fastapi.testclient import TestClient
    import app as app_module
    from api.routes import investigate
    investigate.INVESTIGATIONS.clear()
    yield TestClient(app_module.app), investigate
    investigate.INVESTIGATIONS.clear()


def run(client, investigate, seed, domains):
    with mock.patch.object(investigate, "core_investigate", return_value=fake_result(seed, domains)):
        jid = client.post("/api/investigate", json={"target": seed}).json()["job_id"]
        for _ in range(100):
            job = client.get(f"/api/investigate/{jid}").json()
            if job["status"] != "running":
                return jid, job
            time.sleep(0.02)
    raise AssertionError("investigation did not finish")


def test_saved_listed_reopened_diffed_and_deleted(client):
    c, investigate = client
    jid, job = run(c, investigate, "evil-paypal.example.com", [("evil-paypal.example.com", "seed"), ("a-evil.com", "high")])
    assert job["result"]["saved"] is True and job["result"]["changes"] is None          # first time: nothing to compare
    time.sleep(0.01)
    jid2, job2 = run(c, investigate, "evil-paypal.example.com", [("evil-paypal.example.com", "seed"), ("b-evil.com", "high")])
    ch = job2["result"]["changes"]
    assert (ch["previous_id"], ch["new_domains"], ch["gone_domains"], ch["newly_linked"]) == (jid, ["b-evil.com"], ["a-evil.com"], ["b-evil.com"])

    lst = c.get("/api/investigations").json()
    assert lst["total"] == 2 and [i["id"] for i in lst["items"]] == [jid2, jid]                # newest first
    assert lst["items"][0]["summary"]["mode"] == "malicious" and "result" not in lst["items"][0]
    assert c.get("/api/investigations?q=paypal").json()["total"] == 2
    assert c.get("/api/investigations?q=.*").json()["total"] == 0                               # regex characters are literal

    investigate.INVESTIGATIONS.clear()                                                           # server restarted: memory is gone
    full = c.get(f"/api/investigations/{jid}").json()
    assert full["seed"] == "evil-paypal.example.com" and full["id"] == jid and full["history"]["id"] == jid
    csv_text = c.get(f"/api/investigate/{jid}/iocs.csv").text                                    # export still works from history
    assert "a-evil.com" in csv_text

    assert c.get("/api/investigations/not-an-id").status_code == 404
    assert c.delete(f"/api/investigations/{jid}", headers={"Origin": "https://evil.example"}).status_code == 403
    assert c.delete(f"/api/investigations/{jid}").json() == {"deleted": 1}
    assert c.get(f"/api/investigations/{jid}").status_code == 404
    assert c.get("/api/investigations").json()["total"] == 1


def test_oversized_results_are_trimmed_to_fit(isolated_store):
    db = isolated_store.db
    big = fake_result("big.example.com", [(f"d{i}.com", "low") for i in range(40)])
    for d in big["domains"]:
        d["favicon"] = {"mmh3": 1, "preview": "data:image/png;base64," + "A" * 400_000}
    with mock.patch.object(hist, "MAX_DOC_BYTES", 2 * 1024 * 1024):
        meta = hist.save(db, "0123456789ab", {"depth": 2}, big)
    assert meta["trimmed"] is True and meta["size_bytes"] < 2 * 1024 * 1024
    got = hist.get(db, "0123456789ab")
    assert len(got["domains"]) == 40 and "preview" not in got["domains"][0]["favicon"]


def test_keys_with_dots_are_stored_safely(isolated_store):
    r = fake_result("x.example.com", [("x.example.com", "seed")])
    r["actor"]["targets"] = {"paypal.com": 3}
    hist.save(isolated_store.db, "abcdefabcdef", {}, r)
    assert hist.get(isolated_store.db, "abcdefabcdef")["actor"]["targets"] == {"paypal_com": 3}
