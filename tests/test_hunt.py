"""Offline tests for the impersonation hunt: permutations, verification, scoring, pipeline and API."""
import time
import unittest
from io import BytesIO
from unittest import mock

from PIL import Image, ImageDraw

from core import hunter, verifier
from core.crawler import FaviconCrawler
from core.domains import split_host
from core.hasher import analyze_icon_bytes
from core.permutations import generate_permutations, permutation_stats, to_ascii

try:
    from fastapi.testclient import TestClient
    import app as app_module
    HAVE_CLIENT = True
except Exception:
    HAVE_CLIENT = False


def _logo(shift=0, fmt="PNG"):
    """A patterned image (solid colours have an uninformative pHash)."""
    img = Image.new("RGB", (64, 64), "white")
    d = ImageDraw.Draw(img)
    d.rectangle([8 + shift, 8, 30 + shift, 56], fill=(200, 20, 20))
    d.ellipse([34, 10, 58, 34], fill=(20, 20, 160))
    buf = BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()


BRAND_ICON = _logo()
OTHER_ICON = Image.new("RGB", (64, 64), "white")
ImageDraw.Draw(OTHER_ICON).line([0, 0, 64, 64], fill="black", width=9)
_b = BytesIO()
OTHER_ICON.save(_b, format="PNG")
OTHER_ICON = _b.getvalue()


# ============================================================== permutations
class TestPermutations(unittest.TestCase):
    def test_depths_grow_and_exclude_original(self):
        sizes = {d: len(generate_permutations("adani.com", d)) for d in ("quick", "standard", "deep")}
        self.assertLess(sizes["quick"], sizes["standard"])
        self.assertLess(sizes["standard"], sizes["deep"])
        self.assertGreater(sizes["quick"], 80)
        for d in ("quick", "standard", "deep"):
            self.assertNotIn("adani.com", {p["domain"] for p in generate_permutations("adani.com", d)})

    def test_expected_lookalikes_present(self):
        doms = {p["domain"]: p["fuzzer"] for p in generate_permutations("adani.com", "standard")}
        self.assertEqual(doms.get("adanl.com"), "homoglyph")          # i -> l
        self.assertEqual(doms.get("adni.com"), "omission")
        self.assertEqual(doms.get("daani.com"), "transposition")
        self.assertEqual(doms.get("adani-login.com"), "combosquat")
        self.assertEqual(doms.get("adani.net"), "tld-swap")
        self.assertIn("xn--dani-43d.com", doms)                       # Cyrillic a
        self.assertIn("adanii.com", doms)

    def test_multipart_suffix_keeps_suffix_and_fuzzes_label(self):
        doms = {p["domain"] for p in generate_permutations("bbc.co.uk", "quick")}
        self.assertIn("bbbc.co.uk", doms)
        self.assertIn("bbc.uk", doms)  # deeper ccTLD swap
        self.assertTrue(all(not d.endswith(".co.co.uk") for d in doms))
        for d in doms:
            _, label, suffix = split_host(d)
            self.assertTrue(label and suffix, d)

    def test_all_candidates_are_valid_hostnames(self):
        for p in generate_permutations("gi-de.com", "deep"):
            for label in p["domain"].split("."):
                self.assertTrue(0 < len(label) <= 63, p)
                self.assertFalse(label.startswith("-") or label.endswith("-"), p)
                self.assertRegex(label, r"^[a-z0-9-]+$")

    def test_idn_display_form(self):
        idn = [p for p in generate_permutations("paypal.com", "standard") if p["fuzzer"] == "idn-homoglyph"]
        self.assertTrue(idn)
        for p in idn[:20]:
            self.assertTrue(p["domain"].startswith("xn--"))
            self.assertEqual(to_ascii(p["unicode"].split(".")[0]), p["domain"].split(".")[0])

    def test_extra_keywords_and_stats(self):
        perms = generate_permutations("adani.com", "quick", extra_keywords=["ports"])
        self.assertIn("adani-ports.com", {p["domain"] for p in perms})
        self.assertEqual(sum(permutation_stats(perms).values()), len(perms))


# ============================================================== scoring
def _cand(**kw):
    base = {"domain": "adani-login.com", "fuzzer": "combosquat", "sources": ["permutation"],
            "dns": {"a": ["1.2.3.4"], "aaaa": [], "mx": [], "ns": []}, "evidence": None, "rdap": None}
    base.update(kw)
    return base


class TestScoring(unittest.TestCase):
    def test_exact_favicon_password_new_domain_is_high_risk(self):
        ev = {"http": {"status": 200}, "favicon": {"exact_match": True}, "password_form": True,
              "brand_in_title": True, "title": "Adani Login"}
        score, verdict, reasons = verifier.score_candidate(_cand(evidence=ev, rdap={"age_days": 5}))
        self.assertGreaterEqual(score, 70)
        self.assertEqual(verdict, "phishing")
        self.assertTrue(any("byte-identical" in r for r in reasons))
        self.assertTrue(any("5 days ago" in r for r in reasons))

    def test_redirect_to_brand_is_capped(self):
        ev = {"http": {"status": 200}, "redirect_brand": True, "favicon": {"exact_match": True}}
        score, verdict, _ = verifier.score_candidate(_cand(evidence=ev))
        self.assertEqual(verdict, "redirect_brand")
        self.assertLessEqual(score, 15)

    def test_brand_owned_cert(self):
        ev = {"http": {"status": 200}, "cert_org_match": True, "favicon": {"exact_match": True}}
        self.assertEqual(verifier.score_candidate(_cand(evidence=ev))[1], "brand_owned")

    def test_parked_and_no_website(self):
        parked = {"http": {"status": 200}, "parked": True, "parked_reason": "parking name servers"}
        self.assertEqual(verifier.score_candidate(_cand(evidence=parked))[1], "parked")
        no_web = _cand(dns={"a": [], "aaaa": [], "mx": ["mx.x"], "ns": ["ns1.x"]})
        self.assertEqual(verifier.score_candidate(no_web)[1], "no_website")

    def test_unrelated_live_site_stays_low(self):
        ev = {"http": {"status": 200}, "title": "Some bakery"}
        score, verdict, _ = verifier.score_candidate(_cand(domain="adanl.com", fuzzer="homoglyph", evidence=ev))
        self.assertLess(score, 45)
        self.assertEqual(verdict, "live_unrelated")

    def test_new_lookalike_with_mail_is_suspicious(self):
        # gi-be.com pattern: 6 days old, IIS default page, MX set up, no brand content yet
        c = _cand(domain="gi-be.com", fuzzer="homoglyph", rdap={"age_days": 6},
                  dns={"a": ["1.2.3.4"], "aaaa": [], "mx": ["mx.gi-be.com"], "ns": []},
                  evidence={"http": {"status": 200}, "title": ""})
        score, verdict, reasons = verifier.score_candidate(c)
        self.assertEqual(verdict, "suspicious")
        self.assertTrue(any("watch for a campaign" in r for r in reasons))
        old = dict(c, rdap={"age_days": 900})
        self.assertEqual(verifier.score_candidate(old)[1], "live_unrelated")

    def test_uninformative_phash_ignored(self):
        self.assertIsNone(verifier.phash_distance("0000000000000000", "0000000000000000"))
        self.assertIsNone(verifier.phash_distance(None, "8f8f8f8f8f8f8f8f"))


# ============================================================== verifier
def _brand_profile(**over):
    a = analyze_icon_bytes(BRAND_ICON)
    prof = {"domain": "adani.com", "title": "Adani Group: Home", "tokens": ["adani"], "allowlist": ["adani.com"],
            "favicon_mmh3": {a["mmh3"]}, "favicon_sha256": {a["sha256"]}, "any_sha256": {a["sha256"]},
            "phashes": [(a["phash"], "favicon")], "analytics": {"GTM-ABCD123"},
            "words": {"adani", "group", "energy", "ports", "infrastructure"}, "cert_org": "Adani Enterprises"}
    prof.update(over)
    return prof


class FakeSite:
    """Replaces verifier._fetch with an in-memory site map: url -> (status, final_url, headers, body)."""

    def __init__(self, pages):
        self.pages = pages

    def __call__(self, crawler, url, max_bytes, timeout):
        if url not in self.pages:
            return None
        status, final, ctype, body = self.pages[url]
        return status, final, {"content-type": ctype}, body, []


class TestVerifier(unittest.TestCase):
    def run_verify(self, pages, host="adani-login.com", dns=None, brand=None):
        with mock.patch.object(verifier, "_fetch", FakeSite(pages)), mock.patch.object(verifier, "cert_info", return_value=None):
            return verifier.verify_candidate(host, dns or {"a": ["1.2.3.4"], "ns": []}, brand or _brand_profile(), FaviconCrawler())

    def test_cloned_phishing_page(self):
        html = (b"<html><head><title>Adani Group | Secure Login</title><link rel='icon' href='/fav.png'>"
                b"<script src='https://www.googletagmanager.com/gtm.js?id=GTM-ABCD123'></script></head><body>"
                b"<img src='https://www.adani.com/logo.png'><form><input type='password'></form>"
                b"Adani group energy ports infrastructure</body></html>")
        ev = self.run_verify({
            "https://adani-login.com/": (200, "https://adani-login.com/", "text/html", html),
            "https://adani-login.com/fav.png": (200, "https://adani-login.com/fav.png", "image/png", BRAND_ICON),
        })
        self.assertTrue(ev["favicon"]["exact_match"])
        self.assertEqual(ev["visual_distance"], 0)
        self.assertTrue(ev["password_form"])
        self.assertEqual(ev["brand_resources"], 1)
        self.assertEqual(ev["shared_analytics"], ["GTM-ABCD123"])
        self.assertTrue(ev["brand_in_title"])
        self.assertGreater(ev["text_similarity"], 0.5)
        self.assertTrue(ev["preview"].startswith("data:image/png;base64,"))
        score, verdict, _ = verifier.score_candidate(_cand(evidence=ev))
        self.assertEqual((score, verdict), (100, "phishing"))

    def test_resaved_logo_matches_visually(self):
        html = b"<html><head><title>Welcome</title><link rel='icon' href='/f.jpg'></head><body>hi</body></html>"
        ev = self.run_verify({
            "https://adani-login.com/": (200, "https://adani-login.com/", "text/html", html),
            "https://adani-login.com/f.jpg": (200, "https://adani-login.com/f.jpg", "image/jpeg", _logo(shift=1, fmt="JPEG")),
        })
        self.assertFalse(ev["favicon"]["exact_match"])
        self.assertIsNotNone(ev["visual_distance"])
        self.assertLessEqual(ev["visual_distance"], 6)

    def test_title_echoing_own_domain_is_not_brand_content(self):
        html = b"<html><head><title>adaniy.com</title></head><body>Coming soon</body></html>"
        ev = self.run_verify({"https://adaniy.com/": (200, "https://adaniy.com/", "text/html", html)}, host="adaniy.com")
        self.assertFalse(ev["brand_in_title"])

    def test_parking_page_and_redirect_to_brand(self):
        parked = b"<html><head><title>adanii.com</title></head><body>This domain is for sale! Make an offer.</body></html>"
        ev = self.run_verify({"https://adanii.com/": (200, "https://adanii.com/", "text/html", parked)}, host="adanii.com")
        self.assertTrue(ev["parked"])
        ev = self.run_verify({"https://adani.net/": (200, "https://www.adani.com/", "text/html", b"<html><title>Adani</title></html>")},
                             host="adani.net")
        self.assertTrue(ev["redirect_brand"])

    def test_parking_nameservers_and_http_fallback(self):
        html = b"<html><head><title>x</title></head><body>hello</body></html>"
        ev = self.run_verify({"http://adanl.com/": (200, "http://adanl.com/", "text/html", html)}, host="adanl.com",
                             dns={"a": ["1.1.1.1"], "ns": ["ns1.sedoparking.com"]})
        self.assertEqual(ev["http"]["status"], 200)
        self.assertTrue(ev["parked"])

    def test_unreachable_host(self):
        ev = self.run_verify({}, host="adanl.com")
        self.assertIsNone(ev["http"])


# ============================================================== pipeline
def _fake_dns(names, **kw):
    out = {}
    for n in names:
        live = n in ("adani-login.com", "adanl.com", "adani.secure-portal.xyz")
        reg = live or n in ("adani.net",)
        out[n] = {"domain": n, "a": ["1.2.3.4"] if live else [], "aaaa": [], "mx": ["mx.x"] if n == "adani.net" else [],
                  "ns": ["ns1.x"] if reg else [], "status": "resolves" if live else ("registered" if reg else "nxdomain"),
                  "registered": reg}
    return out


def _fake_verify(host, dns, brand, crawler, timeout=8):
    if host == "adani-login.com":
        return {"http": {"status": 200}, "favicon": {"exact_match": True}, "password_form": True, "brand_in_title": True,
                "title": "Adani Login", "preview": None}
    return {"http": {"status": 200}, "title": "Unrelated", "preview": None}


def _ihit(host, source, match, ip=None, port=None):
    return {"host": host, "ip": ip, "port": port, "url": None, "title": "t", "time": "", "source": source,
            "extra": {}, "match": match, "label": match}


class TestHuntPipeline(unittest.TestCase):
    def test_run_hunt_merges_sources_and_ranks(self):
        scan = {"domain": "adani.com", "resolved_url": "https://www.adani.com/", "reachable": True,
                "icons": [{"kind": "favicon", "is_primary": True, **analyze_icon_bytes(BRAND_ICON), "url": "https://www.adani.com/favicon.ico", "_raw_bytes": BRAND_ICON}]}
        ct = {"hosts": {"adani.secure-portal.xyz": {"first_seen": "2026-11-01", "last_seen": "2026-11-20", "issuer": "Let's Encrypt", "certs": 2},
                        "mail.adani.com": {"first_seen": "2020-01-01", "last_seen": "2026-01-01", "issuer": "DigiCert", "certs": 9}},
              "error": None}
        stages = []
        intel = {"status": [{"source": "urlscan", "match": "asset_hash", "label": "x", "query": "q", "count": 4, "error": None, "ran": True}],
                 "hits": [
                     _ihit("adani-verify.top", "urlscan", "asset_hash"),         # unregistered now -> offline
                     _ihit(None, "shodan", "favicon_hash", ip="5.6.7.8", port=8443),  # IP only -> infrastructure
                     _ihit("en.wikipedia.org", "google-lens", "lens"),          # big platform -> ignored
                     _ihit("portal.adani.com", "urlscan", "dork"),              # own domain -> ignored
                     _ihit("adanl.com", "urlscan", "dork"),                     # merges into permutation
                 ]}
        feed = {"hits": [{"host": "adani-kyc-update.com", "url": "http://adani-kyc-update.com/login", "feed": "openphish",
                          "feed_name": "OpenPhish", "via": "host"},
                         {"host": "adanl.com", "url": None, "feed": "phishingdb", "feed_name": "Phishing.Database", "via": "host"}],
                "status": [{"feed": "openphish", "name": "OpenPhish", "count": 1, "error": None}],
                "errors": ["Phishing.Database download failed (Timeout); using the cached copy"]}
        with mock.patch.object(FaviconCrawler, "scan", return_value=scan), \
                mock.patch.object(hunter.feeds, "match", return_value=feed), \
                mock.patch.object(hunter, "run_intel", return_value=intel), \
                mock.patch.object(hunter, "extract_asset_pivots", return_value={"analytics": [], "assets": []}), \
                mock.patch.object(hunter, "brand_allowlist", return_value=["adani.com"]), \
                mock.patch.object(hunter, "build_brand_profile", return_value=_brand_profile()), \
                mock.patch.object(hunter, "crtsh_search", return_value=ct), \
                mock.patch.object(hunter, "resolve_domains", side_effect=_fake_dns), \
                mock.patch.object(hunter, "verify_candidate", side_effect=_fake_verify), \
                mock.patch.object(hunter, "rdap_lookup", return_value={"age_days": 3, "created": "2026-11-21"}):
            result = hunter.run_hunt("https://www.adani.com/", depth="quick", progress=lambda s, p, m, st: stages.append(s))

        doms = [c["domain"] for c in result["candidates"]]
        self.assertEqual(doms[0], "adani-login.com")
        self.assertEqual(result["candidates"][0]["verdict"], "phishing")
        self.assertIn("adani.secure-portal.xyz", doms)       # brand only in subdomain -> host tracked
        self.assertNotIn("mail.adani.com", doms)              # own domain never reported
        sub = next(c for c in result["candidates"] if c["domain"] == "adani.secure-portal.xyz")
        self.assertEqual(sub["fuzzer"], "brand-subdomain")
        self.assertIn("crt.sh", sub["sources"])
        self.assertEqual(result["stats"]["registered"], 6)  # 4 from DNS + 2 listed / intel-confirmed kits now offline
        listed = next(c for c in result["candidates"] if c["domain"] == "adani-kyc-update.com")
        self.assertEqual(listed["verdict"], "offline")
        self.assertEqual(listed["fuzzer"], "feed-listed")
        self.assertTrue(any("phishing feeds (OpenPhish)" in r for r in listed["reasons"]))
        adanl_feed = next(c for c in result["candidates"] if c["domain"] == "adanl.com")
        self.assertIn("phishingdb", adanl_feed["sources"])
        self.assertTrue(any("Phishing.Database" in r for r in adanl_feed["reasons"]))
        self.assertIn("using the cached copy", " ".join(result["errors"]))
        self.assertEqual(result["feeds"][0]["name"], "OpenPhish")
        offline = next(c for c in result["candidates"] if c["domain"] == "adani-verify.top")
        self.assertEqual(offline["verdict"], "offline")
        self.assertNotIn("en.wikipedia.org", doms)
        self.assertNotIn("wikipedia.org", doms)
        self.assertEqual(result["infrastructure"][0]["ip"], "5.6.7.8")
        adanl = next(c for c in result["candidates"] if c["domain"] == "adanl.com")
        self.assertEqual(adanl["fuzzer"], "homoglyph")
        self.assertIn("urlscan", adanl["sources"])
        self.assertTrue(result["search_dorks"])
        self.assertTrue(result["intel"]["plan"])
        self.assertEqual(stages[-1], "done")
        self.assertIn("combined", result["queries"])
        self.assertIn("master", result["dorks"]["fofa"])
        rows = hunter.hunt_csv_rows(result)
        self.assertEqual(set(rows[0]), set(hunter.HUNT_CSV_FIELDS))
        exported = hunter.hunt_for_export(result)
        self.assertNotIn("_raw_bytes", exported["brand"]["icons"][0])

    def test_cancel(self):
        import threading
        ev = threading.Event()
        ev.set()
        with self.assertRaises(hunter.HuntCancelled):
            hunter.run_hunt("adani.com", cancel=ev)



# ============================================================== network phases overlap
class TestHuntOverlap(unittest.TestCase):
    """The hunt must wait for the slowest network phase, not the sum of them."""

    def run_hunt(self, **patches):
        import threading
        scan = {"domain": "adani.com", "resolved_url": "https://www.adani.com/", "reachable": True,
                "icons": [{"kind": "favicon", "is_primary": True, **analyze_icon_bytes(BRAND_ICON), "url": "https://www.adani.com/favicon.ico", "_raw_bytes": BRAND_ICON}]}
        defaults = {
            "crtsh_search": mock.Mock(return_value={"hosts": {}, "error": None}),
            "run_intel": mock.Mock(return_value={"hits": [], "status": []}),
            "verify_candidate": mock.Mock(side_effect=_fake_verify),
            "rdap_lookup": mock.Mock(return_value={"age_days": 9, "created": "2026-11-01"}),
            "resolve_domains": mock.Mock(side_effect=_fake_dns),
        }
        defaults.update(patches)
        feeds_match = defaults.pop("feeds_match", mock.Mock(return_value={"hits": [], "status": [], "errors": []}))
        stack = [mock.patch.object(FaviconCrawler, "scan", return_value=scan),
                 mock.patch.object(hunter.feeds, "match", feeds_match),
                 mock.patch.object(hunter, "extract_asset_pivots", return_value={"analytics": [], "assets": []}),
                 mock.patch.object(hunter, "brand_allowlist", return_value=["adani.com"]),
                 mock.patch.object(hunter, "build_brand_profile", return_value=_brand_profile())]
        stack += [mock.patch.object(hunter, name, value) for name, value in defaults.items()]
        for m in stack:
            m.start()
            self.addCleanup(m.stop)
        return hunter.run_hunt("adani.com", depth="quick")

    def test_ct_feeds_and_intel_start_together(self):
        import threading
        barrier = threading.Barrier(3, timeout=5)
        seen = []

        def meet(name, value):
            def fn(*a, **k):
                if name not in seen:                       # each source waits once for the other two
                    seen.append(name)
                    barrier.wait()                         # sequential execution would break the barrier (timeout)
                return value
            return fn

        result = self.run_hunt(
            crtsh_search=mock.Mock(side_effect=meet("ct", {"hosts": {}, "error": None})),
            run_intel=mock.Mock(side_effect=meet("intel", {"hits": [], "status": []})),
            feeds_match=mock.Mock(side_effect=meet("feeds", {"hits": [], "status": [], "errors": []})),
        )
        self.assertEqual(sorted(seen), ["ct", "feeds", "intel"])
        self.assertFalse(barrier.broken)
        self.assertEqual(result["errors"], [])

    def test_rdap_runs_while_sites_are_inspected(self):
        import threading
        rdap_started = threading.Event()
        problems = []

        def rdap(domain, *a, **k):
            rdap_started.set()
            return {"age_days": 3, "created": "2026-11-20", "registrar": "R"}

        def verify(host, dns, brand, crawler, timeout=8):
            if not rdap_started.wait(5):                  # inspection must not start before RDAP does, nor RDAP wait for inspection
                problems.append(host)
            return _fake_verify(host, dns, brand, crawler, timeout)

        result = self.run_hunt(verify_candidate=mock.Mock(side_effect=verify), rdap_lookup=mock.Mock(side_effect=rdap))
        self.assertEqual(problems, [])
        self.assertTrue(rdap_started.is_set())
        top = next(c for c in result["candidates"] if c["domain"] == "adani-login.com")
        self.assertEqual(top["rdap"]["age_days"], 3)                       # still merged into the candidate and its score
        self.assertTrue(any("3 days ago" in r for r in top["reasons"]))

    def test_domains_found_risky_by_inspection_get_a_late_lookup(self):
        """With the preliminary RDAP list capped, a domain that inspection reveals as a clone still gets its data."""
        asked = []

        def rdap(domain, *a, **k):
            asked.append(domain)
            return {"age_days": 2, "created": "2026-11-22"}

        def verify(host, dns, brand, crawler, timeout=8):
            if host == "adanl.com":                              # lowest preliminary score, but it clones the brand
                return {"http": {"status": 200}, "favicon": {"exact_match": True}, "password_form": True, "brand_in_title": True,
                        "title": "Adani Login", "preview": None}
            return {"http": {"status": 200}, "title": "Unrelated", "preview": None}

        with mock.patch.object(hunter, "MAX_RDAP", 1):
            result = self.run_hunt(verify_candidate=mock.Mock(side_effect=verify), rdap_lookup=mock.Mock(side_effect=rdap))
        self.assertIn("adani.net", asked)                        # highest preliminary score: asked up front
        self.assertIn("adanl.com", asked)                        # risky after inspection: asked late
        self.assertEqual(len(asked), len(set(asked)))            # never twice
        clone = next(c for c in result["candidates"] if c["domain"] == "adanl.com")
        self.assertEqual(clone["verdict"], "phishing")
        self.assertEqual(clone["rdap"]["age_days"], 2)

@unittest.skipUnless(HAVE_CLIENT, "fastapi TestClient (httpx) not installed")
class TestHuntApi(unittest.TestCase):
    def test_job_lifecycle(self):
        fake = {"target": "adani.com", "depth": "quick", "brand": {"icons": [], "allowlist": ["adani.com"]},
                "stats": {"high_risk": 0}, "candidates": [], "queries": {}, "dorks": {}, "errors": []}

        def fake_run(target, progress=None, **kw):
            progress("dns", 40, "DNS", {"generated": 10})
            return fake

        client = TestClient(app_module.app)
        with mock.patch.object(app_module, "run_hunt", side_effect=fake_run):
            r = client.post("/api/hunt", json={"target": "adani.com", "depth": "quick"})
            self.assertEqual(r.status_code, 200)
            job_id = r.json()["job_id"]
            for _ in range(50):
                job = client.get(f"/api/hunt/{job_id}").json()
                if job["status"] != "running":
                    break
                time.sleep(0.05)
        self.assertEqual(job["status"], "done")
        self.assertEqual(job["result"]["target"], "adani.com")
        self.assertEqual(client.post("/api/hunt", json={"target": "x.com", "depth": "huge"}).status_code, 400)
        self.assertEqual(client.get("/api/hunt/nope").status_code, 404)


if __name__ == "__main__":
    unittest.main()
