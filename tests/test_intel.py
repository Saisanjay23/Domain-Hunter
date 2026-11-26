"""Offline tests for Phase 2: config, platform clients, pivots, search dorks, intel plan and intel scoring."""
import base64
import os
import tempfile
import unittest
from unittest import mock

from bs4 import BeautifulSoup

from core import config, hunter, pivots, sources, verifier
from core.crawler import FetchResult


class FakeResp:
    def __init__(self, status=200, data=None):
        self.status_code = status
        self._data = data

    def json(self):
        if self._data is None:
            raise ValueError("no json")
        return self._data


class TestConfig(unittest.TestCase):
    @mock.patch.dict(os.environ, {"FREE_ONLY_MODE": "0"})  # exercises the paid-platform path
    def test_env_file_and_status_never_exposes_values(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, ".env")
            with open(path, "w") as f:
                f.write("# comment\nSHODAN_API_KEY = 'abc123'\nexport FOFA_KEY=fk\nEMPTY=\n")
            with mock.patch.object(config, "ENV_FILE", path), mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("SHODAN_API_KEY", None)
                os.environ.pop("FOFA_KEY", None)
                config.load_env()
                self.assertEqual(config.get("SHODAN_API_KEY"), "abc123")
                self.assertEqual(config.get("FOFA_KEY"), "fk")
                status = {s["id"]: s for s in config.sources_status()}
                self.assertTrue(status["shodan"]["enabled"])
                self.assertEqual(status["urlscan"]["mode"], "anonymous" if not config.get("URLSCAN_API_KEY") else "key")
                self.assertNotIn("abc123", repr(status))
                os.environ.pop("SHODAN_API_KEY", None)
                os.environ.pop("FOFA_KEY", None)

    def test_env_file_changes_are_picked_up_without_restart(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, ".env")
            with mock.patch.object(config, "ENV_FILE", path), mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("CENSYS_PAT", None)
                config._from_file.discard("CENSYS_PAT")
                self.assertIsNone(config.get("CENSYS_PAT"))          # no file yet
                with open(path, "w") as f:
                    f.write("CENSYS_PAT=first\n")
                self.assertEqual(config.get("CENSYS_PAT"), "first")  # file created
                with open(path, "w") as f:
                    f.write("CENSYS_PAT=second\n")
                os.utime(path, (1, 1))                                # force a different mtime
                self.assertEqual(config.get("CENSYS_PAT"), "second")  # file edited
                with open(path, "w") as f:
                    f.write("# removed\n")
                os.utime(path, (2, 2))
                self.assertIsNone(config.get("CENSYS_PAT"))          # key removed
        config._loaded_mtime = None  # re-read the real .env next time

    def test_existing_env_wins(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, ".env")
            with open(path, "w") as f:
                f.write("SERPAPI_KEY=fromfile\n")
            with mock.patch.dict(os.environ, {"SERPAPI_KEY": "fromenv"}):
                config.load_env(path)
                self.assertEqual(config.get("SERPAPI_KEY"), "fromenv")


class TestSources(unittest.TestCase):
    def setUp(self):
        from core.keypool import POOL
        POOL.reset()  # rotation state is process-wide; start every test with healthy keys

    def test_urlscan_normalises_hits(self):
        data = {"results": [{"page": {"domain": "adani-login.pages.dev", "ip": "1.1.1.1", "url": "https://adani-login.pages.dev/",
                                      "title": "Adani Login", "asnname": "CLOUDFLARENET"},
                             "task": {"time": "2026-11-20T00:00:00Z"}, "result": "https://urlscan.io/api/v1/result/x/"}]}
        with mock.patch("requests.get", return_value=FakeResp(200, data)):
            hits = sources.urlscan_search("q")
        self.assertEqual(hits[0]["host"], "adani-login.pages.dev")
        self.assertEqual(hits[0]["title"], "Adani Login")
        self.assertEqual(hits[0]["extra"]["asn"], "CLOUDFLARENET")

    def test_shodan_ip_only_and_errors_hide_key(self):
        data = {"matches": [{"ip_str": "5.6.7.8", "port": 443, "hostnames": [], "http": {"title": "Login"}, "org": "Evil"}]}
        with mock.patch.dict(os.environ, {"SHODAN_API_KEY": "SECRETKEY"}):
            with mock.patch("requests.get", return_value=FakeResp(200, data)):
                hits = sources.shodan_search("http.favicon.hash:1")
            self.assertIsNone(hits[0]["host"])
            self.assertEqual((hits[0]["ip"], hits[0]["port"]), ("5.6.7.8", 443))
            import requests
            with mock.patch("requests.get", side_effect=requests.ConnectionError("https://api.shodan.io/?key=SECRETKEY")):
                with self.assertRaises(sources.SourceError) as ctx:
                    sources.shodan_search("x")
            self.assertNotIn("SECRETKEY", str(ctx.exception))
            with mock.patch("requests.get", return_value=FakeResp(401, {})):
                with self.assertRaises(sources.SourceError):
                    sources.shodan_search("x")

    def test_missing_key_raises(self):
        with mock.patch.dict(os.environ, {"FOFA_KEY": ""}):
            with self.assertRaises(sources.SourceError):
                sources.fofa_search("x")

    def test_fofa_encodes_query_and_parses_rows(self):
        captured = {}

        def fake_get(url, params=None, headers=None, timeout=None):
            captured.update(params)
            return FakeResp(200, {"error": False, "results": [["https://adani-kyc.com", "9.9.9.9", "443", "adani-kyc.com", "KYC", "2026-11-01"]]})

        with mock.patch.dict(os.environ, {"FOFA_KEY": "k"}), mock.patch("requests.get", side_effect=fake_get):
            hits = sources.fofa_search('icon_hash="1"')
        self.assertEqual(base64.b64decode(captured["qbase64"]).decode(), 'icon_hash="1"')
        self.assertEqual(hits[0]["host"], "adani-kyc.com")
        self.assertEqual(hits[0]["port"], 443)

    def test_fofa_chinese_errors_translated(self):
        self.assertEqual(sources.fofa_error_text("[-700] 账号无效"), "invalid key or account (code -700)")
        self.assertEqual(sources.fofa_error_text("plain english"), "plain english")
        with mock.patch.dict(os.environ, {"FOFA_KEY": "k"}), \
                mock.patch("requests.get", return_value=FakeResp(200, {"error": True, "errmsg": "[-700] 账号无效"})):
            with self.assertRaises(sources.SourceError) as ctx:
                sources.fofa_search("x")
        self.assertIn("invalid key", str(ctx.exception))

    def test_censys_walks_resources(self):
        data = {"result": {"hits": [{"webproperty_v1": {"resource": {"hostname": "adani-pay.net", "port": 443,
                                                                      "endpoints": [{"http": {"html_title": "Adani Pay"}}]}}},
                                    {"host_v1": {"resource": {"ip": "7.7.7.7"}}}]}}
        with mock.patch.dict(os.environ, {"CENSYS_PAT": "t"}), mock.patch("requests.post", return_value=FakeResp(200, data)):
            hits = sources.censys_search("q")
        self.assertEqual(hits[0]["host"], "adani-pay.net")
        self.assertEqual(hits[0]["title"], "Adani Pay")
        self.assertEqual(hits[1]["ip"], "7.7.7.7")

    def test_serpapi_lens(self):
        data = {"visual_matches": [{"link": "https://fake-adani.com/a", "title": "Adani", "source": "fake"}]}
        with mock.patch.dict(os.environ, {"SERPAPI_KEY": "s"}), mock.patch("requests.get", return_value=FakeResp(200, data)):
            hits = sources.serpapi_lens("https://www.adani.com/logo.png")
        self.assertEqual(hits[0]["host"], "fake-adani.com")


class FakeCrawler:
    def __init__(self, files):
        self.files = files

    def _safe_get(self, url, max_bytes=0):
        body = self.files.get(url)
        if body is None:
            return None
        return FetchResult(url=url, status=200, headers={"content-type": "application/javascript"}, content=body)


class TestPivots(unittest.TestCase):
    def test_asset_pivots_skip_libraries_and_third_parties(self):
        html = """<html><head>
          <script src="/static/app.4f2a.js"></script>
          <script src="/static/jquery.min.js"></script>
          <script src="/static/ngrlCaptcha.min.js"></script>
          <script src="/static/datadog-DNPX-sGw.js"></script>
          <script src="https://cdn.other.com/brand.js"></script>
          <link rel="stylesheet" href="https://www.adani.com/css/site.css">
          <script>gtag('config','G-ABCDEF1234');</script></head></html>"""
        crawler = FakeCrawler({
            "https://www.adani.com/static/app.4f2a.js": b"x" * 2000,
            "https://www.adani.com/static/jquery.min.js": b"j" * 2000,
            "https://www.adani.com/css/site.css": b"c" * 3000,
        })
        p = pivots.extract_asset_pivots(BeautifulSoup(html, "html.parser"), "https://www.adani.com/", ["adani.com"], crawler)
        urls = [a["url"] for a in p["assets"]]
        self.assertEqual(urls, ["https://www.adani.com/static/app.4f2a.js", "https://www.adani.com/css/site.css"])
        self.assertEqual(p["analytics"], ["G-ABCDEF1234"])
        q = pivots.pivot_queries(p, ["adani.com"])
        self.assertTrue(any(x["platform"] == "urlscan" and x["query"].startswith("hash:(") for x in q))
        self.assertTrue(any(x["query"].startswith('body="G-ABCDEF1234"') for x in q))

    def test_search_engine_dorks(self):
        dorks = pivots.search_engine_dorks("adani.com", "adani", ["adani"])
        groups = {d["group"] for d in dorks}
        self.assertIn("Free hosting & site builders", groups)
        self.assertIn("Fake recruitment & helplines", groups)
        for d in dorks:
            self.assertEqual(set(d["links"]), {"google", "bing", "duckduckgo", "yandex"})
        imp = [d for d in dorks if d["group"] == "Impersonation pages"]
        self.assertTrue(all("-site:adani.com" in d["query"] for d in imp))

    @mock.patch.dict(os.environ, {"FREE_ONLY_MODE": "0"})  # exercises the paid-platform path

    def test_intel_plan(self):
        icons = [{"kind": "favicon", "sha256": "a" * 64}, {"kind": "logo", "sha256": "b" * 64}, {"kind": "subdomain", "sha256": "c" * 64}]
        plan = pivots.build_intel_plan(
            {"shodan": "http.favicon.hash:1", "fofa": 'icon_hash="1"', "censys": "x"}, icons,
            {"analytics": ["GTM-ABC12"], "assets": [{"sha256": "d" * 64}]},
            {"urlscan": {"domain_wildcard": "page.domain:adani*", "title_spoof": 'page.title:"adani"'},
             "shodan": {"title_spoof": "t"}, "fofa": {"master": "m"}, "censys": {"title_spoof": "c"}},
            ["adani.com"], "adani", ["adani"])
        by = {(p["source"], p["match"]) for p in plan}
        self.assertIn(("urlscan", "asset_hash"), by)
        self.assertIn(("urlscan", "hosting"), by)
        self.assertIn(("shodan", "analytics"), by)
        asset_q = next(p["query"] for p in plan if p["match"] == "asset_hash")
        self.assertIn("a" * 64, asset_q)
        self.assertIn("b" * 64, asset_q)
        self.assertNotIn("c" * 64, asset_q)  # subdomain-portal icons excluded
        self.assertNotIn("d" * 64, asset_q)  # JS/CSS is searched separately: it only scores weakly
        self.assertIn("NOT page.apexDomain:adani.com", asset_q)
        code_q = next(p["query"] for p in plan if p["match"] == "code_hash")
        self.assertIn("d" * 64, code_q)
        self.assertNotIn("a" * 64, code_q)
        shodan_fav = next(p["query"] for p in plan if p["source"] == "shodan" and p["match"] == "favicon_hash")
        self.assertTrue(shodan_fav.endswith("-hostname:adani.com"))

    def test_shared_code_files_are_dropped(self):
        """WordPress plugin files seen on thousands of sites must not become 'brand files' (hair-salon false positive)."""
        counts = {"w" * 64: 1939, "x" * 64: 17, "y" * 64: 10000, "z" * 64: 200, "q" * 64: None}
        assets = [{"url": f"https://b.com/{k[0]}.js", "sha256": k} for k in counts]
        calls = []

        def count(sha):
            calls.append(sha)
            if counts[sha] is None:
                raise RuntimeError("URLScan unreachable")
            return counts[sha]

        out = pivots.drop_shared_assets({"analytics": ["GTM-1"], "assets": assets}, count)
        self.assertEqual(sorted(a["sha256"][0] for a in out["assets"]), ["x", "z"])   # rare (17) and at the threshold (200)
        self.assertEqual(out["dropped_shared"], 3)                                    # popular, huge, and unknown (fail closed)
        self.assertEqual({a["sha256"][0]: a["seen_on"] for a in out["assets"]}, {"x": 17, "z": 200})
        self.assertEqual(out["analytics"], ["GTM-1"])
        self.assertEqual(len(calls), 5)

    def test_urlscan_total_reads_the_reported_total(self):
        with mock.patch("requests.get", return_value=FakeResp(200, {"results": [], "total": 1302, "has_more": False})) as g:
            self.assertEqual(sources.urlscan_total("hash:abc"), 1302)
        self.assertEqual(g.call_args.kwargs["params"], {"q": "hash:abc", "size": 1})

    def test_code_file_match_alone_cannot_make_a_page_high_risk(self):
        """The exact false positive seen in the cyfirma.com hunt: a new WordPress site with a login form."""
        salon = {"domain": "emmanuelsluxehair.com", "fuzzer": "intel-code_hash", "sources": ["urlscan"],
                 "dns": {"a": ["1.2.3.4"], "aaaa": [], "mx": ["mx.example"], "ns": []}, "dns_status": "resolves",
                 "intel": [{"source": "urlscan", "match": "code_hash"}],
                 "evidence": {"http": {"status": 200}, "password_form": True}, "rdap": {"age_days": 0}}
        score, verdict, reasons = verifier.score_candidate(salon)
        self.assertLess(score, 45)
        self.assertEqual(verdict, "live_unrelated")
        self.assertTrue(any("weak signal" in r for r in reasons))
        # ...whereas a favicon / logo image match is still decisive
        clone = {**salon, "fuzzer": "intel-asset_hash", "intel": [{"source": "urlscan", "match": "asset_hash"}]}
        self.assertEqual(verifier.score_candidate(clone)[1], "phishing")

    def test_lens_image_urls(self):
        icons = [{"kind": "logo", "url": "https://a.com/big.png", "format": "PNG", "dimensions": "600x200"},
                 {"kind": "logo", "url": "https://a.com/l.svg", "format": "SVG", "dimensions": "100x40"},
                 {"kind": "favicon", "url": "https://a.com/favicon.ico", "format": "ICO", "dimensions": "32x32"},
                 {"kind": "favicon", "url": "https://a.com/touch.png", "format": "PNG", "dimensions": "180x180"}]
        self.assertEqual(pivots.lens_image_urls(icons), ["https://a.com/big.png", "https://a.com/touch.png"])


class TestIntelRunAndScore(unittest.TestCase):
    def setUp(self):
        from core.keypool import POOL
        POOL.reset()

    @mock.patch.dict(os.environ, {"FREE_ONLY_MODE": "0"})  # exercises the paid-platform path

    def test_run_intel_skips_unconfigured_and_reports_errors(self):
        plan = [{"source": "urlscan", "match": "dork", "label": "L", "query": "q1"},
                {"source": "shodan", "match": "favicon_hash", "label": "F", "query": "q2"}]

        def fake_urlscan(q):
            raise sources.SourceError("HTTP 429: rate limited, try again later")

        with mock.patch.dict(os.environ, {"SHODAN_API_KEY": "", "SERPAPI_KEY": ""}), \
                mock.patch.dict(hunter.SEARCHERS, {"urlscan": fake_urlscan}):
            out = hunter.run_intel(plan, ["https://a.com/logo.png"])
        status = {(s["source"], s["ran"]): s for s in out["status"]}
        self.assertIn("429", status[("urlscan", True)]["error"])
        self.assertEqual(status[("shodan", False)]["error"], "no API key configured")
        self.assertIn(("serpapi", False), status)

    def test_intel_matches_drive_score(self):
        cand = {"domain": "secure-portal.xyz", "fuzzer": "intel-favicon_hash", "sources": ["shodan"],
                "dns": {"a": ["1.2.3.4"], "aaaa": [], "mx": [], "ns": []}, "dns_status": "resolves",
                "intel": [{"source": "shodan", "match": "favicon_hash"}, {"source": "fofa", "match": "favicon_hash"},
                          {"source": "urlscan", "match": "asset_hash"}],
                "evidence": {"http": {"status": 200}, "password_form": True}, "rdap": None}
        score, verdict, reasons = verifier.score_candidate(cand)
        self.assertEqual(verdict, "phishing")
        self.assertTrue(any("FOFA, Shodan favicon-hash" in r for r in reasons))

    def test_offline_kit(self):
        cand = {"domain": "adani-verify.top", "fuzzer": "intel-asset_hash", "sources": ["urlscan"],
                "dns": {"a": [], "aaaa": [], "mx": [], "ns": []}, "dns_status": "nxdomain",
                "intel": [{"source": "urlscan", "match": "asset_hash"}], "evidence": None, "rdap": None}
        score, verdict, _ = verifier.score_candidate(cand)
        self.assertEqual(verdict, "offline")
        self.assertLessEqual(score, 60)


if __name__ == "__main__":
    unittest.main()
