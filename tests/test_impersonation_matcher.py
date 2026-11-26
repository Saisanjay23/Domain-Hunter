"""
Comprehensive test suite for Domain Hunter's enhanced impersonation engine:
  - PSL-based subdomain impersonation detection (gi-de.astrobale-core.tech, multi-level subdomains)
  - Independent multi-keyword evaluation (gi-de, Giesecke, Devrient, G+D, Giesecke+Devrient)
  - Exact, typosquatting, homograph/IDN/Punycode, and mixed-script detection
  - False-positive suppression on common dictionary-word collisions (goods, gdpr, guided, gideon)
  - Multi-source automated OSINT integrations (Bing RSS, DDG challenge-safe, Wayback, VirusTotal, WHOIS, HackerTarget)
  - End-to-end hunt pipeline deduplication, NXDOMAIN offline handling, and CSV/JSON export fields
"""

from __future__ import annotations

import os
from unittest import mock

import pytest

from core import config, discovery, domain_matcher, hunter, permutations, sources, verifier


GI_DE_KEYWORDS = ["gi-de", "Giesecke", "Devrient", "G+D", "Giesecke+Devrient"]


class _FakeResp:
    def __init__(self, status_code: int = 200, json_data=None, text: str = ""):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text
        self.headers = {}

    def json(self):
        if self._json_data is None:
            raise ValueError("no json")
        return self._json_data


# ============================================================== 1. Matching Engine Scenarios
def test_exact_brand_and_combo_variants():
    for dom in ("gi-de-security.com", "gi-de-login.net", "secure-gi-de.org"):
        res = domain_matcher.evaluate_domain_match(dom, "gi-de.com", keywords=GI_DE_KEYWORDS)
        assert res["matched_keyword"] == "gi-de"
        assert res["technique_key"] == "combosquat"
        assert res["similarity_percent"] >= 74.0
        assert not res["is_benign_collision"]


def test_subdomain_impersonation_gi_de_astrobale_and_nested():
    # Primary critical scenario: keyword inside subdomain of unrelated third-party root domain
    r1 = domain_matcher.evaluate_domain_match("gi-de.astrobale-core.tech", "gi-de.com", keywords=GI_DE_KEYWORDS)
    assert r1["domain"] == "gi-de.astrobale-core.tech"
    assert r1["registered_domain"] == "astrobale-core.tech"
    assert r1["matching_subdomain"] == "gi-de"
    assert r1["matched_keyword"] == "gi-de"
    assert r1["is_subdomain_impersonation"] is True
    assert r1["technique_key"] == "subdomain_impersonation"
    assert r1["similarity_percent"] == 100.0

    # Nested multi-level subdomain impersonation
    r2 = domain_matcher.evaluate_domain_match("login.gi-de.attacker-domain.com", "gi-de.com", keywords=GI_DE_KEYWORDS)
    assert r2["registered_domain"] == "attacker-domain.com"
    assert r2["matching_subdomain"] == "gi-de"
    assert r2["is_subdomain_impersonation"] is True

    # Hyphenated brand-lure inside subdomain under unrelated root
    r3 = domain_matcher.evaluate_domain_match("gi-de-security.malicious-site.org", "gi-de.com", keywords=GI_DE_KEYWORDS)
    assert r3["registered_domain"] == "malicious-site.org"
    assert r3["matching_subdomain"] == "gi-de-security"
    assert r3["is_subdomain_impersonation"] is True


def test_typosquatting_mechanisms_detected():
    cases = [
        ("gi-ed.com", "typosquat_transposition", "gi-de"),
        ("gieseck.com", "typosquat_omission", "Giesecke"),
        ("gieseecke.com", "typosquat_repetition", "Giesecke"),
        ("gieseckex.com", "typosquat_insertion", "Giesecke"),
        ("gieseckw.com", "typosquat_keyboard", "Giesecke"),
        ("gi-do.com", "typosquat_substitution", "gi-de"),
        ("gide.com", "hyphen_variation", "gi-de"),
    ]
    for dom, expected_tech, expected_kw in cases:
        res = domain_matcher.evaluate_domain_match(dom, "gi-de.com", keywords=GI_DE_KEYWORDS)
        assert res["technique_key"] == expected_tech, f"Expected {expected_tech} for {dom}, got {res}"
        assert res["matched_keyword"] == expected_kw
        assert res["similarity_percent"] >= 60.0


def test_homograph_idn_and_punycode_mixed_script():
    # Cyrillic 'і' (\u0456) and 'е' (\u0435) impersonating 'gi-de.com'
    cyrillic_host = "g\u0456-d\u0435.com"
    ace = cyrillic_host.encode("idna").decode("ascii")
    assert ace.startswith("xn--")

    res_ace = domain_matcher.evaluate_domain_match(ace, "gi-de.com", keywords=GI_DE_KEYWORDS)
    assert res_ace["is_idn"] is True
    assert res_ace["mixed_script"] is True
    assert "Cyrillic" in res_ace["scripts"]
    assert res_ace["technique_key"] == "homograph_idn"
    assert res_ace["similarity_percent"] >= 88.0
    assert res_ace["unicode"] == cyrillic_host

    # Scoring promotes mixed-script IDN homograph to Suspicious / Potential Impersonation when live
    cand = {
        "domain": ace, "fuzzer": "intel-dork", "sources": ["crt.sh"],
        "dns": {"a": ["203.0.113.99"], "aaaa": [], "mx": [], "ns": []},
        "evidence": {"http": {"status": 200}, "title": "Portal"},
        "match_meta": res_ace,
    }
    score, verdict, _ = verifier.score_candidate(cand)
    assert score >= 30
    assert verdict == "suspicious"
    assert domain_matcher.classify_candidate(cand, score, verdict) == "Potential Impersonation"


def test_independent_multi_keyword_evaluation():
    expectations = [
        ("giesecke-portal.com", "Giesecke", False),
        ("devrient-login.net", "Devrient", False),
        ("gd-login.org", "G+D", False),
        ("gd.attacker-host.net", "G+D", True),
        ("gieseckedevrient-security.com", "Giesecke+Devrient", False),
    ]
    for dom, kw, expect_sub in expectations:
        res = domain_matcher.evaluate_domain_match(dom, "gi-de.com", keywords=GI_DE_KEYWORDS)
        assert res["matched_keyword"] == kw, f"{dom}: {res}"
        assert res["is_subdomain_impersonation"] is expect_sub

    # Permutation engine also generates independent variants per analyst keyword
    perms = permutations.generate_permutations("gi-de.com", depth="quick", extra_keywords=GI_DE_KEYWORDS)
    perm_domains = {p["domain"] for p in perms}
    assert "giesecke.com" in perm_domains
    assert "devrient.net" in perm_domains
    assert "gd-login.com" in perm_domains


def test_false_positive_suppression_on_unrelated_common_words():
    brand = {"domain": "gi-de.com", "tokens": ["gi-de", "giesecke", "devrient", "gieseckedevrient"], "raw_keywords": GI_DE_KEYWORDS, "allowlist": ["gi-de.com"]}
    for benign_dom in ("guided-tours.com", "gideonsjeweler.com", "goods-store.com", "gdpr-compliance.org"):
        cand = {
            "domain": benign_dom, "fuzzer": "intel-dork", "sources": ["bing"],
            "dns": {"a": ["198.51.100.1"], "aaaa": [], "mx": ["mx.example.com"], "ns": []},
            "dns_status": "resolves",
            "evidence": {"http": {"status": 200}, "title": f"Welcome to {benign_dom}"},
            "rdap": {"age_days": 1200},
        }
        score, verdict, _ = verifier.score_candidate(cand, brand)
        assert score <= 20, f"Unexpected high score {score} on benign collision {benign_dom}"
        assert verdict == "live_unrelated"
        cand["match_meta"] = domain_matcher.evaluate_domain_match(benign_dom, "gi-de.com", keywords=GI_DE_KEYWORDS)
        assert domain_matcher.classify_candidate(cand, score, verdict) == "Benign/Unrelated"


def test_legitimate_brand_domains_excluded_or_benign():
    res = domain_matcher.evaluate_domain_match("portal.gi-de.com", "gi-de.com", keywords=GI_DE_KEYWORDS, allowlist=["gi-de.com", "giesecke-devrient.com"])
    assert res["is_own_domain"] is True
    assert res["is_subdomain_impersonation"] is False


# ============================================================== 2. Discovery Sources & WHOIS
def test_bing_rss_duckduckgo_challenge_guard_and_wayback(monkeypatch):
    monkeypatch.setattr(sources, "_FREE_CACHE", {})
    rss_xml = """<?xml version="1.0" encoding="utf-8"?>
    <rss version="2.0"><channel>
      <item><title>Gi-De Login Portal</title><link>https://gi-de.astrobale-core.tech/login</link></item>
      <item><title>Duplicate host</title><link>https://gi-de.astrobale-core.tech/auth</link></item>
    </channel></rss>"""
    with mock.patch("requests.get", return_value=_FakeResp(200, text=rss_xml)):
        hits = sources.bing_search('intitle:"Giesecke+Devrient" -site:gi-de.com')
    assert len(hits) == 1
    assert hits[0]["host"] == "gi-de.astrobale-core.tech"
    assert hits[0]["source"] == "bing"

    # DuckDuckGo HTTP 202 anti-bot challenge: MUST abort HTML scrape cleanly (no CAPTCHA bypass) and try IA fallback
    def fake_ddg_get(url, **kw):
        if "html.duckduckgo.com" in url:
            return _FakeResp(202, text="<div class='anomaly-modal'>Please solve challenge</div>")
        return _FakeResp(200, json_data={"AbstractURL": "", "Results": [], "RelatedTopics": []})

    with mock.patch("requests.get", side_effect=fake_ddg_get):
        with pytest.raises(sources.SourceError, match="challenged"):
            sources.duckduckgo_search("gi-de -site:gi-de.com")

    cdx_rows = [["original", "timestamp", "statuscode"], ["https://gi-de.workers.dev/login", "20261125010101", "200"]]
    with mock.patch("requests.get", return_value=_FakeResp(200, json_data=cdx_rows)):
        wb = sources.wayback_search("*.workers.dev/*gi-de*")
    assert len(wb) == 1
    assert wb[0]["host"] == "gi-de.workers.dev"
    assert wb[0]["time"] == "2026-11-25"


def test_virustotal_search_and_check_key(monkeypatch):
    with mock.patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "vt_test_secret_1234"}):
        assert "virustotal" in config.SOURCES
        assert config.is_configured("virustotal")

        vt_payload = {
            "data": [{
                "type": "domain",
                "id": "giesecke-verify.top",
                "attributes": {
                    "last_analysis_stats": {"malicious": 4, "suspicious": 1},
                    "creation_date": 1732406400,
                },
            }]
        }
        with mock.patch("requests.get", return_value=_FakeResp(200, json_data=vt_payload)):
            hits = sources.virustotal_search("giesecke")
        assert len(hits) == 1
        assert hits[0]["host"] == "giesecke-verify.top"
        assert hits[0]["malicious_votes"] == 4

        with mock.patch("requests.get", return_value=_FakeResp(200, json_data={"data": []})):
            ck = sources.check_key("virustotal")
        assert ck["ok"] is True


def test_whois_fallback_and_hackertarget_reverse_ip(monkeypatch):
    monkeypatch.setattr(discovery, "_REG_CACHE", {})
    iana_raw = "refer:        whois.nic.example\n"
    nic_raw = "Domain Name: EXAMPLE-PHISH.TECH\nRegistrar: Example Registrar LLC\nCreation Date: 2026-11-20T00:00:00Z\n"
    with mock.patch.object(discovery, "rdap_lookup", return_value=None), \
            mock.patch.object(discovery, "_whois_raw", side_effect=[iana_raw, nic_raw]):
        reg = discovery.registration_lookup("gi-de.example-phish.tech")
    assert reg is not None
    assert reg["registrar"] == "Example Registrar LLC"
    assert reg["age_days"] is not None

    monkeypatch.setattr(sources, "_FREE_CACHE", {})
    with mock.patch("requests.get", return_value=_FakeResp(200, text="gi-de.astrobale-core.tech\ngiesecke-portal.net\n")):
        rev = sources.hackertarget_reverse_ip("203.0.113.50")
    assert rev == ["gi-de.astrobale-core.tech", "giesecke-portal.net"]


# ============================================================== 3. End-to-End Pipeline Integration
def test_end_to_end_hunt_with_keywords_subdomains_dedup_and_nxdomain():
    scan = {"domain": "gi-de.com", "resolved_url": "https://www.gi-de.com/", "reachable": True, "icons": []}
    brand = {
        "domain": "gi-de.com", "title": "Giesecke+Devrient | Official",
        "tokens": ["gi-de", "giesecke", "devrient", "gieseckedevrient"],
        "raw_keywords": GI_DE_KEYWORDS,
        "allowlist": ["gi-de.com", "giesecke-devrient.com"],
        "favicon_mmh3": set(), "favicon_sha256": set(), "any_sha256": set(),
        "phashes": [], "analytics": set(), "words": {"giesecke", "devrient"}, "cert_org": "Giesecke+Devrient",
    }
    ct = {
        "hosts": {
            "gi-de.astrobale-core.tech": {"first_seen": "2026-11-24", "last_seen": "2026-11-25", "issuer": "Let's Encrypt", "certs": 1},
            "login.gi-de.attacker-domain.com": {"first_seen": "2026-11-24", "last_seen": "2026-11-25", "issuer": "ZeroSSL", "certs": 1},
            "portal.gi-de.com": {"first_seen": "2024-01-01", "last_seen": "2026-01-01", "issuer": "DigiCert", "certs": 4},
        },
        "error": None,
    }
    intel = {
        "status": [{"source": "urlscan", "match": "subdomain_spoof", "label": "sub", "query": "q", "count": 2, "error": None, "ran": True}],
        "hits": [
            {"host": "gi-de.astrobale-core.tech", "ip": "203.0.113.5", "port": 443, "url": "https://gi-de.astrobale-core.tech",
             "title": "Giesecke+Devrient Sign In", "time": "2026-11-25", "source": "urlscan", "extra": {}, "match": "subdomain_spoof", "label": "sub"},
            {"host": "devrient-offline.top", "ip": None, "port": None, "url": "https://devrient-offline.top",
             "title": "Devrient SSO", "time": "2026-11-25", "source": "urlscan", "extra": {}, "match": "daily_title", "label": "title"},
        ],
    }

    def fake_dns(hosts, **_kw):
        out = {}
        for h in hosts:
            if h in ("gi-de.astrobale-core.tech", "login.gi-de.attacker-domain.com", "giesecke-security.com"):
                out[h] = {"domain": h, "a": ["203.0.113.5"], "aaaa": [], "mx": ["mx.evil.com"], "ns": ["ns1.evil.com"], "status": "resolves", "registered": True}
            else:
                out[h] = {"domain": h, "a": [], "aaaa": [], "mx": [], "ns": [], "status": "nxdomain", "registered": False}
        return out

    def fake_verify(host, dns, b, crawler, timeout=8):
        if host == "gi-de.astrobale-core.tech":
            return {"http": {"status": 200}, "title": "Giesecke+Devrient Sign In", "brand_in_title": True, "password_form": True}
        return {"http": {"status": 200}, "title": "Auth Portal"}

    with mock.patch.object(hunter.FaviconCrawler, "scan", return_value=scan), \
            mock.patch.object(hunter.feeds, "match", return_value={"hits": [], "status": [], "errors": []}), \
            mock.patch.object(hunter, "run_intel", return_value=intel), \
            mock.patch.object(hunter, "extract_asset_pivots", return_value={"analytics": [], "assets": []}), \
            mock.patch.object(hunter, "brand_allowlist", return_value=["gi-de.com", "giesecke-devrient.com"]), \
            mock.patch.object(hunter, "build_brand_profile", return_value=brand), \
            mock.patch.object(hunter, "crtsh_search", return_value=ct), \
            mock.patch.object(hunter, "resolve_domains", side_effect=fake_dns), \
            mock.patch.object(hunter, "verify_candidate", side_effect=fake_verify), \
            mock.patch.object(hunter, "rdap_lookup", return_value={"age_days": 4, "created": "2026-11-22"}):
        result = hunter.run_hunt("gi-de.com", depth="quick", extra_keywords=GI_DE_KEYWORDS)

    by_dom = {c["domain"]: c for c in result["candidates"]}
    # Critical: subdomain impersonations stay intact with full FQDN (no collapse into root domains), deduplicated across crt.sh & urlscan
    assert len(result["candidates"]) == len(by_dom)
    assert "portal.gi-de.com" not in by_dom
    assert "gi-de.astrobale-core.tech" in by_dom
    sub = by_dom["gi-de.astrobale-core.tech"]
    assert set(sub["sources"]) == {"crt.sh", "urlscan"}
    assert sub["registered_domain"] == "astrobale-core.tech"
    assert sub["matching_subdomain"] == "gi-de"
    assert sub["matched_keyword"] == "gi-de"
    assert sub["classification"] == "Confirmed Impersonation"

    assert "login.gi-de.attacker-domain.com" in by_dom
    nested = by_dom["login.gi-de.attacker-domain.com"]
    assert nested["registered_domain"] == "attacker-domain.com"
    assert nested["matching_subdomain"] == "gi-de"
    assert nested["classification"] in ("Potential Impersonation", "Confirmed Impersonation")

    assert "devrient-offline.top" in by_dom
    off = by_dom["devrient-offline.top"]
    assert off["verdict"] == "offline"
    assert off["classification"] == "Potential Impersonation"
    assert off["dns_status"] == "nxdomain"

    csv_rows = hunter.hunt_csv_rows(result)
    assert set(csv_rows[0]) == set(hunter.HUNT_CSV_FIELDS)
    sub_csv = next(r for r in csv_rows if r["domain"] == "gi-de.astrobale-core.tech")
    assert sub_csv["registered_domain"] == "astrobale-core.tech"
    assert sub_csv["matching_subdomain"] == "gi-de"
    assert sub_csv["classification"] == "Confirmed Impersonation"


def test_bing_rss_client_side_operator_enforcement_and_redirect_unwrap(monkeypatch):
    import base64

    monkeypatch.setattr(sources, "_FREE_CACHE", {})
    wrapped_target = "a1" + base64.urlsafe_b64encode(b"https://paypal-verify.workers.dev/signin").decode().rstrip("=")
    rss_xml = f"""<?xml version="1.0" encoding="utf-8"?>
    <rss version="2.0"><channel>
      <item><title>PayPal Official</title><link>https://www.paypal.com/myaccount</link></item>
      <item><title>PayPal Sandbox</title><link>https://www-v2.sandbox.paypal.com/wf/signin</link></item>
      <item><title>PayPal - Wikipedia</title><link>https://en.wikipedia.org/wiki/PayPal</link></item>
      <item><title>PayPal Sign In Clone</title><link>https://www.bing.com/ck/a?!&amp;&amp;u={wrapped_target}</link></item>
    </channel></rss>"""
    q = '"paypal" (site:workers.dev OR site:vercel.app) -site:paypal.com'
    with mock.patch("requests.get", return_value=_FakeResp(200, text=rss_xml)):
        hits = sources.bing_search(q)
    assert [h["host"] for h in hits] == ["paypal-verify.workers.dev"]
    assert hits[0]["url"] == "https://paypal-verify.workers.dev/signin"

    monkeypatch.setattr(sources, "_FREE_CACHE", {})
    with mock.patch("requests.get", return_value=_FakeResp(200, text=rss_xml)):
        hits_title = sources.bing_search('intitle:"PayPal" -site:paypal.com')
    hosts_title = [h["host"] for h in hits_title]
    assert "www.paypal.com" not in hosts_title
    assert "www-v2.sandbox.paypal.com" not in hosts_title
    assert "paypal-verify.workers.dev" in hosts_title


def test_hunt_filters_out_bing_false_positives_and_keeps_real_hits():
    scan = {"domain": "gi-de.com", "resolved_url": "https://www.gi-de.com/", "reachable": True, "icons": []}
    brand = {
        "domain": "gi-de.com", "title": "Giesecke+Devrient | SecurityTech",
        "tokens": ["gi-de", "giesecke", "devrient", "gieseckedevrient"],
        "raw_keywords": GI_DE_KEYWORDS,
        "allowlist": ["gi-de.com", "giesecke-devrient.com"],
        "favicon_mmh3": set(), "favicon_sha256": set(), "any_sha256": set(),
        "phashes": [], "analytics": set(), "words": {"giesecke", "devrient"}, "cert_org": "Giesecke+Devrient",
    }
    bing_hits = [
        # Real impersonations that MUST survive
        {"host": "gi-de.astrobale-core.tech", "ip": None, "port": None, "url": "https://gi-de.astrobale-core.tech/login",
         "title": "Giesecke+Devrient Login", "time": "", "source": "bing", "match": "dork", "label": "bing"},
        {"host": "giesecke-portal.workers.dev", "ip": None, "port": None, "url": "https://giesecke-portal.workers.dev/",
         "title": "Sign In", "time": "", "source": "bing", "match": "dork", "label": "bing"},
        {"host": "portal-9124.vercel.app", "ip": None, "port": None, "url": "https://portal-9124.vercel.app/giesecke-login",
         "title": "Customer Portal", "time": "", "source": "bing", "match": "dork", "label": "bing"},
        # False positives observed from live Bing RSS that MUST be suppressed
        {"host": "en.wikipedia.org", "ip": None, "port": None, "url": "https://en.wikipedia.org/wiki/Giesecke%2BDevrient",
         "title": "Giesecke+Devrient - Wikipedia", "time": "", "source": "bing", "match": "dork", "label": "bing"},
        {"host": "www.scam-detector.com", "ip": None, "port": None, "url": "https://www.scam-detector.com/validator/gi-de-com-review/",
         "title": "gi-de.com Reviews", "time": "", "source": "bing", "match": "dork", "label": "bing"},
        {"host": "www.whois.com", "ip": None, "port": None, "url": "https://www.whois.com/whois/gi-de.com",
         "title": "Whois gi-de.com", "time": "", "source": "bing", "match": "dork", "label": "bing"},
        {"host": "www.zhihu.com", "ip": None, "port": None, "url": "https://www.zhihu.com/question/27164322",
         "title": "Unrelated Zhihu thread", "time": "", "source": "bing", "match": "dork", "label": "bing"},
        {"host": "ssc.gov.in", "ip": None, "port": None, "url": "https://ssc.gov.in/",
         "title": "Staff Selection Commission", "time": "", "source": "bing", "match": "dork", "label": "bing"},
        {"host": "vajiramandravi.com", "ip": None, "port": None, "url": "https://vajiramandravi.com/upsc-exam/gi-tag/",
         "title": "GI Tag List", "time": "", "source": "bing", "match": "dork", "label": "bing"},
        {"host": "unrelated-demo.vercel.app", "ip": None, "port": None, "url": "https://unrelated-demo.vercel.app/hello",
         "title": "My React Starter", "time": "", "source": "bing", "match": "dork", "label": "bing"},
    ]
    seen_dns_hosts: list = []

    def fake_dns(hosts, **_kw):
        seen_dns_hosts.extend(hosts)
        return {
            h: {"domain": h, "a": ["203.0.113.9"], "aaaa": [], "mx": [], "ns": [], "status": "resolves", "registered": True}
            for h in hosts
        }

    with mock.patch.object(hunter.FaviconCrawler, "scan", return_value=scan), \
            mock.patch.object(hunter.feeds, "match", return_value={"hits": [], "status": [], "errors": []}), \
            mock.patch.object(hunter, "run_intel", return_value={"status": [], "hits": bing_hits}), \
            mock.patch.object(hunter, "extract_asset_pivots", return_value={"analytics": [], "assets": []}), \
            mock.patch.object(hunter, "brand_allowlist", return_value=["gi-de.com", "giesecke-devrient.com"]), \
            mock.patch.object(hunter, "build_brand_profile", return_value=brand), \
            mock.patch.object(hunter, "crtsh_search", return_value={"hosts": {}, "error": None}), \
            mock.patch.object(hunter, "resolve_domains", side_effect=fake_dns), \
            mock.patch.object(hunter, "verify_candidate", return_value={"http": {"status": 200}, "title": "Portal"}), \
            mock.patch.object(hunter, "rdap_lookup", return_value={"age_days": 5, "created": "2026-11-21"}):
        result = hunter.run_hunt("gi-de.com", depth="quick", extra_keywords=GI_DE_KEYWORDS)

    doms = {c["domain"] for c in result["candidates"]}
    assert {"gi-de.astrobale-core.tech", "giesecke-portal.workers.dev", "portal-9124.vercel.app"} <= doms
    for fp in ("en.wikipedia.org", "wikipedia.org", "www.scam-detector.com", "scam-detector.com",
               "www.whois.com", "whois.com", "www.zhihu.com", "zhihu.com",
               "ssc.gov.in", "vajiramandravi.com", "unrelated-demo.vercel.app"):
        assert fp not in doms
        assert fp not in seen_dns_hosts
