"""Phase 3: phishing feeds, case store (history / triage / diff), takedown output, alerts, scheduler and API guards."""
import json
import os
import time
import unittest
from unittest import mock

from core import alerts, feeds, store as store_mod, takedown
from core.store import StoreError, get_store

try:
    from fastapi.testclient import TestClient
    import app as app_module
    HAVE_CLIENT = True
except Exception:
    HAVE_CLIENT = False


def cand(domain, score=80, verdict="phishing", **kw):
    return {"domain": domain, "score": score, "verdict": verdict, "verdict_label": verdict.title(), "sources": ["urlscan"],
            "reasons": ["favicon is byte-identical to the brand favicon"], "dns": {"a": ["104.16.1.1"], "mx": []}, **kw}


def result(target="paypal.com", cands=None, **stats):
    return {"target": target, "depth": "quick", "stats": {"registered": len(cands or []), **stats}, "candidates": cands or []}


# ============================================================== feeds
class TestFeeds(unittest.TestCase):
    def test_token_matching_avoids_look_alike_words(self):
        m = feeds.token_matches
        for host in ("adani.ho27.co", "adani-login.com", "secure-adani.com", "secureadani.com", "adanipower.in", "a.b-adani-x.com"):
            self.assertTrue(m(host, "adani"), host)
        for host in ("al-madani.org", "rivanirahmadani.com", "mradani.ml", "madani-tours.com", "example.com"):
            self.assertFalse(m(host, "adani"), host)
        self.assertTrue(m("paypalsecure.cc", "paypal"))      # 6+ characters: substring is enough
        self.assertTrue(m("my-paypal-verify.com", "paypal"))

    def test_match_ranks_filters_and_reports_download_failures(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "openphish.txt"), "w") as f:
                f.write("http://adani-kyc.com/login\nhttps://evil.pages.dev/adani/pay\nhttps://sites.google.com/view/adani\nhttps://adani.com/real\n")
            with open(os.path.join(d, "phishing-domains-active.txt"), "w") as f:
                f.write("# comment\nadani-login.com\nsecure.adani-pay.in\nmadani-tours.com\nadani.com\nxx-adani-yy-long-name.com\n")
            ok = {"ok": True, "downloaded": False, "age": 10}
            with mock.patch.object(feeds, "CACHE_DIR", d), mock.patch.object(feeds, "refresh", return_value=ok):
                feeds._memory.clear()
                r = feeds.match(["adani"], ["adani.com"])
            by_feed = {}
            for h in r["hits"]:
                by_feed.setdefault(h["feed"], []).append(h)
            self.assertEqual({h["host"] for h in by_feed["openphish"]}, {"adani-kyc.com", "evil.pages.dev"})
            self.assertEqual(next(h for h in by_feed["openphish"] if h["host"] == "evil.pages.dev")["via"], "path")
            domains = {h["host"] for h in by_feed["phishingdb"]}
            self.assertEqual(domains, {"adani-login.com", "adani-pay.in", "xx-adani-yy-long-name.com"})  # own domain + madani excluded
            self.assertNotIn("sites.google.com", {h["host"] for h in r["hits"]})      # path-only on a big platform is ignored
            ranked = [h["host"] for h in by_feed["phishingdb"]]
            self.assertEqual(ranked[0], "adani-pay.in")                               # shortest (closest to the brand) first
            self.assertEqual(ranked[-1], "xx-adani-yy-long-name.com")

            with mock.patch.object(feeds, "CACHE_DIR", d), mock.patch.object(feeds, "refresh", return_value={"ok": False, "error": "OpenPhish download failed (Timeout)"}):
                r = feeds.match(["adani"], [])
            self.assertEqual(r["hits"], [])
            self.assertIn("download failed", " ".join(r["errors"]))

    def test_short_brand_is_skipped_with_a_message(self):
        r = feeds.match(["ing"], [])
        self.assertEqual(r["hits"], [])
        self.assertIn("too short", r["errors"][0])


# ============================================================== store
class TestStore(unittest.TestCase):
    def setUp(self):
        self.s = get_store()

    def test_history_diff_first_seen_and_triage(self):
        r1 = result(cands=[cand("a.com"), cand("b.com", 10, "no_website")])
        self.s.decorate(r1, exclude_id="h1")
        self.assertFalse(r1["stats"]["has_previous"])
        self.assertTrue(all(not c["is_new"] for c in r1["candidates"]))      # first hunt is a baseline, nothing is "new"
        self.s.save_hunt("h1", r1, created=time.time() - 1000)

        r2 = result(cands=[cand("a.com"), cand("c.com", 75)])
        self.s.decorate(r2, exclude_id="h2")
        self.assertEqual([c["is_new"] for c in r2["candidates"]], [False, True])
        self.assertEqual((r2["stats"]["new_domains"], r2["stats"]["new_risky"]), (1, 1))
        self.assertLess(r2["candidates"][0]["first_seen"], time.time() - 900)  # a.com was first seen in hunt 1
        self.s.save_hunt("h2", r2)

        self.assertEqual([h["id"] for h in self.s.list_hunts()], ["h2", "h1"])
        self.assertEqual(self.s.get_hunt("h2")["candidates"][1]["domain"], "c.com")

        self.s.triage_set("paypal.com", "a.com", "false_positive", "partner site")
        again = self.s.get_hunt("h2")
        self.s.decorate(again, compute_new=False)
        self.assertEqual(again["candidates"][0]["triage"]["status"], "false_positive")
        self.assertEqual(again["candidates"][1]["triage"]["status"], "open")
        self.assertTrue(again["candidates"][1]["is_new"])                     # stored flag survives a re-decorate
        self.s.triage_set("paypal.com", "a.com", "open", "")                  # reset removes the row
        self.assertEqual(self.s.triage_get("paypal.com"), {})
        with self.assertRaises(StoreError):
            self.s.triage_set("paypal.com", "a.com", "bogus")
        self.assertTrue(self.s.delete_hunt("h1"))
        self.assertIsNone(self.s.get_hunt("h1"))

    def test_other_brands_do_not_mix(self):
        self.s.save_hunt("h1", result("paypal.com", [cand("a.com")]))
        other = result("netflix.com", [cand("a.com")])
        self.s.decorate(other, exclude_id="h2")
        self.assertFalse(other["stats"]["has_previous"])

    def test_previews_trimmed_to_top_candidates(self):
        many = [cand(f"d{i}.com", score=i, evidence={"preview": "data:image/png;base64,AAAA"}) for i in range(60)]
        self.s.save_hunt("h1", result(cands=many))
        stored = self.s.get_hunt("h1")["candidates"]
        kept = [c for c in stored if (c.get("evidence") or {}).get("preview")]
        self.assertEqual(len(kept), store_mod.PREVIEW_KEEP)
        self.assertEqual(min(c["score"] for c in kept), 60 - store_mod.PREVIEW_KEEP)

    def test_watchlist_webhook_is_masked_and_validated(self):
        url = "https://hooks.slack.com/services/T000/B000/SECRETTOKENXYZ1"
        wid = self.s.watch_add("paypal.com", "quick", 6, 50, url, ["paypal.me"])
        w = self.s.watch_get(wid)
        self.assertNotIn("SECRETTOKEN", json.dumps(w))
        self.assertTrue(w["webhook"]["set"])
        self.assertEqual(self.s.watch_get(wid, include_secret=True)["webhook_url"], url)
        with self.assertRaises(StoreError):
            self.s.watch_add("paypal.com", "quick", 6, 50, "", [])             # duplicate brand
        with self.assertRaises(StoreError):
            self.s.watch_add("x.com", "quick", 6, 50, "ftp://nope", [])        # not http(s)
        self.s.watch_update(wid, enabled=False, webhook_url="")
        w = self.s.watch_get(wid)
        self.assertFalse(w["enabled"])
        self.assertFalse(w["webhook"]["set"])

    def test_alerts(self):
        aid = self.s.alert_add("paypal.com", "high", "t", "b", "h1")
        self.assertEqual(self.s.alert_unread(), 1)
        self.s.alert_mark_read(aid)
        self.assertEqual(self.s.alert_unread(), 0)


# ============================================================== takedown
class TestTakedown(unittest.TestCase):
    def test_email_and_report_are_defanged_and_escaped(self):
        c = cand("paypal-login.xyz", evidence={"http": {"final_url": "https://www.paypal-login.xyz/a", "status": 200},
                                                "title": "<script>alert(1)</script>Pay", "preview": "javascript:alert(1)"},
                 rdap={"registrar": "NameCheap", "created": "2026-11-20T00:00:00Z", "age_days": 4},
                 triage={"status": "confirmed", "note": "<img src=x onerror=alert(2)>"})
        contacts = {"emails": ["abuse@registrar.example"], "hosting": [], "forms": [], "channels": takedown.REPORT_CHANNELS}
        mail = takedown.email_draft(c, "paypal.com", contacts)
        self.assertEqual(mail["to"], "abuse@registrar.example")
        self.assertIn("paypal-login[.]xyz", mail["subject"])
        self.assertNotIn("http://", mail["body"])
        self.assertIn("hxxps://www[.]paypal-login[.]xyz/a", mail["body"])
        page = takedown.evidence_html(c, "paypal.com", contacts)
        self.assertNotIn("<script>alert", page)
        self.assertNotIn("<img src=x", page)
        self.assertNotIn('src="javascript:', page)       # only data:image previews are embedded
        self.assertIn("&lt;script&gt;", page)

    def test_ip_abuse_uses_rdap_and_skips_private_addresses(self):
        takedown._IP_CACHE.clear()
        self.assertIsNone(takedown.ip_abuse("10.1.2.3"))

        class R:
            def __init__(self, data):
                self.data = data

            def json(self):
                return self.data

        rdap = {"name": "CLOUDFLARENET", "handle": "NET-1", "entities": [
            {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Cloudflare, Inc."]]]},
            {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@cloudflare.com"]]]}]}
        with mock.patch.object(takedown, "_ip_service", return_value="https://rdap.example/"), \
                mock.patch.object(takedown.requests, "get", return_value=R(rdap)):
            info = takedown.ip_abuse("104.16.1.1")
        self.assertEqual((info["network"], info["org"], info["abuse_email"]), ("CLOUDFLARENET", "Cloudflare, Inc.", "abuse@cloudflare.com"))
        with mock.patch.object(takedown, "ip_abuse", return_value=info):
            contacts = takedown.abuse_contacts(cand("x.com", rdap={"registrar": "R", "abuse_email": "reg@r.example"}), lookup=True)
        self.assertEqual(contacts["emails"], ["reg@r.example", "abuse@cloudflare.com"])
        self.assertEqual(contacts["forms"][0]["url"], "https://abuse.cloudflare.com/")

    def test_ioc_selection_txt_and_stix(self):
        cands = [cand("a.com", 90), cand("b.com", 50, "suspicious"), cand("c.com", 20, "live_unrelated"),
                 cand("d.com", 95, triage={"status": "false_positive"}), cand("e.com", 10, "no_website", triage={"status": "confirmed"}),
                 cand("f.com", 60, "suspicious", first_seen=1700000000)]
        picked = takedown.select_iocs(cands)
        self.assertEqual([c["domain"] for c in picked], ["a.com", "f.com", "b.com", "e.com"])  # no false positive, no low risk
        self.assertEqual([c["domain"] for c in takedown.select_iocs(cands, statuses=["confirmed"])], ["e.com"])
        txt = takedown.ioc_txt("paypal.com", picked)
        self.assertIn("\na.com\n", txt)
        self.assertNotIn("[.]", txt)
        bundle = takedown.stix_bundle("paypal.com", picked)
        ind = {o["name"]: o for o in bundle["objects"]}
        self.assertEqual(bundle["type"], "bundle")
        one = ind["Impersonation of paypal.com: f.com"]
        self.assertEqual(one["pattern"], "[domain-name:value = 'f.com']")
        self.assertEqual((one["spec_version"], one["pattern_type"], one["confidence"]), ("2.1", "stix", 60))
        self.assertTrue(one["valid_from"].startswith("2023-11-14"))
        again = takedown.stix_bundle("paypal.com", picked)
        self.assertEqual([o["id"] for o in bundle["objects"]], [o["id"] for o in again["objects"]])  # stable ids


# ============================================================== alerts
class TestAlerts(unittest.TestCase):
    def test_baseline_never_notifies_then_only_new_risky_alerts(self):
        base = result(cands=[cand("a.com")], has_previous=False, high_risk=1, suspicious=0)
        note = alerts.compose("paypal.com", base, 45)
        self.assertEqual((note["level"], note["notify"]), ("info", False))

        nxt = result(has_previous=True, cands=[
            cand("old.com", is_new=False), cand("fresh.com", 88, is_new=True), cand("meh.com", 30, "suspicious", is_new=True),
            cand("fp.com", 90, is_new=True, triage={"status": "false_positive"}), cand("quiet.com", 80, "live_unrelated", is_new=True)])
        note = alerts.compose("paypal.com", nxt, 45)
        self.assertTrue(note["notify"])
        self.assertEqual(note["domains"], ["fresh.com"])
        self.assertEqual(note["level"], "high")
        self.assertIn("fresh[.]com", note["body"])
        self.assertIsNone(alerts.compose("paypal.com", result(has_previous=True, cands=[cand("old.com", is_new=False)]), 45))

    def test_webhook_errors_never_leak_the_url(self):
        import requests
        url = "https://hooks.example/services/SECRETTOKEN"
        with mock.patch.object(alerts.requests, "post", side_effect=requests.ConnectionError(url)):
            ok, msg = alerts.send_webhook(url, "t", "b")
        self.assertFalse(ok)
        self.assertNotIn("SECRETTOKEN", msg)

        class R:
            status_code = 404

        with mock.patch.object(alerts.requests, "post", return_value=R()):
            ok, msg = alerts.send_webhook(url, "t", "b")
        self.assertEqual((ok, msg), (False, "webhook rejected the message (HTTP 404)"))


# ============================================================== API
@unittest.skipUnless(HAVE_CLIENT, "fastapi TestClient (httpx) not installed")
class TestCaseApi(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app_module.app)
        self.s = get_store()
        self.s.save_hunt("h1", {**result(cands=[cand("a.com", 90), cand("b.com", 50, "suspicious")]), "stats": {"high_risk": 1}})

    def test_history_triage_and_exports(self):
        listing = self.client.get("/api/hunts").json()["hunts"]
        self.assertEqual(listing[0]["id"], "h1")
        r = self.client.put("/api/triage", json={"brand": "paypal.com", "domain": "a.com", "status": "confirmed", "note": "seen live"})
        self.assertEqual(r.json()["status"], "confirmed")
        self.assertEqual(self.client.put("/api/triage", json={"brand": "paypal.com", "domain": "a.com", "status": "nope"}).status_code, 400)
        hunt = self.client.get("/api/hunts/h1").json()
        self.assertEqual(hunt["candidates"][0]["triage"], {**hunt["candidates"][0]["triage"], "status": "confirmed", "note": "seen live"})
        txt = self.client.get("/api/hunts/h1/ioc?format=txt&min_score=40")
        self.assertEqual(txt.headers["X-IOC-Count"], "2")
        self.assertIn("a.com", txt.text)
        stix = self.client.get("/api/hunts/h1/ioc?format=stix&status=confirmed").json()
        self.assertEqual([o["pattern"] for o in stix["objects"]], ["[domain-name:value = 'a.com']"])
        self.assertEqual(self.client.get("/api/hunts/h1/ioc?format=pdf").status_code, 400)
        self.assertEqual(self.client.get("/api/hunts/nope").status_code, 404)

    def test_takedown_and_report(self):
        contacts = {"domain": "a.com", "registrar": {}, "hosting": [], "forms": [], "emails": ["abuse@x.example"], "channels": []}
        with mock.patch.object(app_module.takedown, "abuse_contacts", return_value=contacts):
            r = self.client.get("/api/hunts/h1/takedown", params={"domain": "a.com"}).json()
            page = self.client.get("/api/hunts/h1/report", params={"domain": "a.com"})
        self.assertEqual(r["email"]["to"], "abuse@x.example")
        self.assertIn("a[.]com", r["email"]["subject"])
        self.assertIn("text/html", page.headers["content-type"])
        self.assertEqual(self.client.get("/api/hunts/h1/takedown", params={"domain": "zzz.com"}).status_code, 404)

    def test_cross_site_writes_are_refused(self):
        evil = {"Origin": "https://evil.example"}
        self.assertEqual(self.client.put("/api/triage", headers=evil, json={"brand": "b", "domain": "d", "status": "confirmed"}).status_code, 403)
        self.assertEqual(self.client.post("/api/watchlist", headers=evil, json={"brand": "paypal.com"}).status_code, 403)
        self.assertEqual(self.client.delete("/api/hunts/h1", headers=evil).status_code, 403)
        self.assertEqual(self.client.post("/api/hunt", headers=evil, json={"target": "paypal.com"}).status_code, 403)
        same = {"Origin": "http://testserver"}
        self.assertEqual(self.client.put("/api/triage", headers=same, json={"brand": "b", "domain": "d", "status": "confirmed"}).status_code, 200)
        self.assertIsNotNone(self.s.get_hunt("h1"))

    def test_job_result_is_saved_diffed_and_survives_restart(self):
        fake = {"target": "adani.com", "depth": "quick", "brand": {"icons": [], "allowlist": ["adani.com"]}, "stats": {"high_risk": 1},
                "candidates": [cand("adani-x.com", 90)], "queries": {}, "dorks": {}, "errors": []}
        with mock.patch.object(app_module, "run_hunt", return_value=fake):
            jid = self.client.post("/api/hunt", json={"target": "adani.com", "depth": "quick"}).json()["job_id"]
            for _ in range(100):
                job = self.client.get(f"/api/hunt/{jid}").json()
                if job["status"] != "running":
                    break
                time.sleep(0.05)
        self.assertEqual(job["status"], "done")
        self.assertEqual(job["result"]["hunt_id"], jid)
        self.assertIn("triage", job["result"]["candidates"][0])
        app_module.HUNT_JOBS.pop(jid, None)                                    # simulate a server restart
        back = self.client.get(f"/api/hunt/{jid}").json()
        self.assertEqual((back["status"], back["result"]["target"]), ("done", "adani.com"))

    def test_watchlist_crud_scheduler_and_alerts(self):
        started = []
        with mock.patch.object(app_module, "_start_watch_hunt", side_effect=lambda w: started.append(w["brand"]) or "j1"):
            r = self.client.post("/api/watchlist", json={"brand": "https://www.Paypal.com/login", "depth": "quick", "interval_hours": 6,
                                                         "webhook_url": "https://hooks.example/SECRETTOKEN", "allowlist": ["paypal.me"]})
            self.assertEqual(r.status_code, 200)
            self.assertNotIn("SECRETTOKEN", r.text)
            w = r.json()["watchlist"][0]
            self.assertEqual((w["brand"], w["allowlist"], w["webhook"]["set"]), ("paypal.com", ["paypal.me"], True))
            self.assertEqual(started, ["paypal.com"])                           # baseline hunt starts immediately
            self.assertEqual(self.client.post("/api/watchlist", json={"brand": "paypal.com"}).status_code, 400)
            self.assertEqual(self.client.post("/api/watchlist", json={"brand": "localhost"}).status_code, 400)

            wid = w["id"]
            now = time.time()
            self.s.watch_update(wid, last_run=now - 3600, last_status="ok")      # ran 1 h ago, interval 6 h
            self.assertEqual(app_module.scheduler_tick(now), [])
            self.s.watch_update(wid, last_run=now - 7 * 3600)
            self.assertEqual(app_module.scheduler_tick(now), ["paypal.com"])     # overdue
            self.s.watch_update(wid, last_run=now - 7 * 3600, enabled=False)
            self.assertEqual(app_module.scheduler_tick(now), [])                 # disabled
            self.assertEqual(self.client.patch(f"/api/watchlist/{wid}", json={"enabled": True, "interval_hours": 12}).json()["watchlist"][0]["interval_hours"], 12)
            self.assertEqual(self.client.post(f"/api/watchlist/{wid}/run").json(), {"job_id": "j1"})

        sent = []
        with mock.patch.object(app_module.alerts_mod, "send_webhook", side_effect=lambda *a, **k: sent.append(a) or (True, "delivered (HTTP 200)")):
            nxt = result(has_previous=True, cands=[cand("fresh.com", 88, is_new=True)])
            app_module._finish_watch(wid, "j9", nxt)
        self.assertEqual(len(sent), 1)
        al = self.client.get("/api/alerts").json()
        self.assertEqual(al["unread"], 1)
        self.assertIn("1 new lookalike", al["alerts"][0]["title"])
        self.assertIn("delivered", al["alerts"][0]["delivery"])
        self.client.post("/api/alerts/read", json={})
        self.assertEqual(self.client.get("/api/alerts").json()["unread"], 0)

        app_module._finish_watch(wid, "j10", None, error="boom")                  # a failed scheduled hunt raises an error alert
        self.assertEqual(self.client.get("/api/alerts").json()["alerts"][0]["level"], "error")
        self.assertEqual(self.client.delete(f"/api/watchlist/{wid}").json()["watchlist"], [])


if __name__ == "__main__":
    unittest.main()
