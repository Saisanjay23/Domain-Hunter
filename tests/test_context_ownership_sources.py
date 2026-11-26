"""
Brand + malicious-context detection, legitimate-ownership evidence, Google Safe Browsing, OTX passive DNS,
source availability checks and the RapidFuzz edit-distance path. All network calls are mocked.
"""

from __future__ import annotations

import random
import string
from contextlib import ExitStack
from unittest import mock

import pytest

from core import bulk, domain_matcher, health, hunter, scoring, sources, verifier

BRAND = "gi-de.com"
KEYWORDS = ["gi-de", "Giesecke", "Devrient", "G+D", "Giesecke+Devrient"]
ALLOW = ["gi-de.com", "giesecke-devrient.com"]


def ev(host, **kw):
    return domain_matcher.evaluate_domain_match(host, BRAND, keywords=KEYWORDS, **kw)


class _Resp:
    def __init__(self, status=200, data=None, headers=None):
        self.status_code, self._data, self.headers, self.text = status, data, headers or {}, ""

    def json(self):
        if self._data is None:
            raise ValueError("no json")
        return self._data

    def close(self):
        pass


# --------------------------------------------------------------------------- brand + malicious context
@pytest.mark.parametrize("host,words", [
    ("gi-de-verification.org", ["verification"]), ("gi-de-banking.com", ["banking"]),
    ("secure-gi-de.com", ["secure"]), ("login.gi-de.attacker.net", ["login"]),
    ("gi-de-authentication.net", ["authentication"]), ("giesecke-payment.com", ["payment"]),
    ("gi-de-wallet-support.com", ["wallet", "support"]),
])
def test_brand_plus_lure_words_are_recorded(host, words):
    r = ev(host)
    assert set(words) <= set(r["context_keywords"]), r["context_keywords"]
    assert any(x.startswith("Brand + malicious context") for x in r["match_reasons"])


def test_brand_glued_to_lure_word_is_a_combosquat_but_glued_to_other_words_is_not():
    assert ev("gidewallet.com")["technique_key"] == "combosquat"
    assert ev("logingide.com")["context_keywords"] == ["login"]
    assert ev("gidelogin.attacker.net")["is_subdomain_impersonation"]
    for benign in ("gidewear.com", "gideon.com", "guided.com"):
        assert ev(benign)["technique_key"] in ("none", "benign_collision"), benign


def test_no_context_without_a_brand_match():
    assert ev("secure-login.com")["context_keywords"] == []
    assert ev("gi-de.astrobale-core.tech")["context_keywords"] == []


def test_lure_context_raises_priority_once():
    plain = bulk.evaluate_domains(BRAND, KEYWORDS, ["gi-de-tours.com"], allowlist=ALLOW)["results"][0]
    lure = bulk.evaluate_domains(BRAND, KEYWORDS, ["gi-de-login.com"], allowlist=ALLOW)["results"][0]
    assert lure["score"] == plain["score"] + scoring.DEFAULT_WEIGHTS["brand_lure_context"]
    assert any(b["signal"] == "brand_lure_context" for b in lure["score_breakdown"])
    # generated combosquat permutations already score the lure: no double counting
    cand = {"domain": "gi-de-login.com", "fuzzer": "combosquat", "sources": ["permutation"], "match_meta": ev("gi-de-login.com"),
            "dns": {"a": ["203.0.113.1"]}, "evidence": None}
    sig = [b["signal"] for b in verifier.score_candidate_detailed(cand)["breakdown"]]
    assert "combosquat_lure" in sig and "brand_lure_context" not in sig


def test_lure_keywords_are_configurable(monkeypatch):
    monkeypatch.setenv("LURE_KEYWORDS", "invoice2fa, -banking, crypto")
    words = scoring.get_lure_words()
    assert "crypto" in words and "invoice2fa" in words and "banking" not in words and "login" in words
    assert "banking" not in ev("gi-de-banking.com")["context_keywords"]
    assert ev("gi-de-crypto.com")["context_keywords"] == ["crypto"]
    monkeypatch.delenv("LURE_KEYWORDS")
    assert scoring.get_lure_words() == scoring.DEFAULT_LURE_WORDS


# --------------------------------------------------------------------------- legitimate ownership evidence
def _owned(dns=None, evidence=None):
    return {"domain": "gi-de.cn", "fuzzer": "tld-swap", "sources": ["permutation"], "match_meta": ev("gi-de.cn"),
            "dns": dns or {"a": ["203.0.113.4"], "aaaa": [], "mx": [], "ns": []}, "dns_status": "resolves",
            "evidence": evidence or {"http": {"status": 200}, "brand_in_title": True, "title": "Giesecke+Devrient China"},
            "rdap": {"age_days": 4000}}


@pytest.mark.parametrize("dns,evidence,needle", [
    ({"a": ["203.0.113.4"], "aaaa": [], "mx": [], "ns": ["ns1.gi-de.com", "ns2.gi-de.com"]}, None, "name servers"),
    ({"a": ["203.0.113.4"], "aaaa": [], "mx": ["mail.giesecke-devrient.com"], "ns": []}, None, "mail servers"),
    (None, {"http": {"status": 200}, "brand_in_title": True, "cert_covers_brand": True}, "certificate"),
])
def test_brand_operated_infrastructure_means_brand_owned(dns, evidence, needle):
    d = verifier.score_candidate_detailed(_owned(dns, evidence), {"allowlist": ALLOW})
    assert d["verdict"] == "brand_owned" and d["score"] <= 10
    assert any(needle in o for o in d["ownership"])
    assert domain_matcher.classify_candidate({**_owned(dns, evidence), "match_meta": ev("gi-de.cn")}, d["score"], d["verdict"]) == "Benign/Unrelated"


def test_third_party_infrastructure_is_not_ownership():
    d = verifier.score_candidate_detailed(_owned({"a": ["1.2.3.4"], "aaaa": [], "mx": ["mx.evil.top"], "ns": ["kim.ns.cloudflare.com"]}),
                                          {"allowlist": ALLOW})
    assert d["verdict"] != "brand_owned" and not d.get("ownership")


def test_cert_covers_brand_rules():
    own = {"san": ["gi-de.cn", "www.gi-de.com"], "san_count": 2, "subject_cn": "gi-de.cn"}
    assert verifier.cert_covers_brand(own, ALLOW)
    assert not verifier.cert_covers_brand({**own, "subject_cn": "sni123.cloudflaressl.com"}, ALLOW)  # shared CDN cert
    assert not verifier.cert_covers_brand({**own, "san_count": 80}, ALLOW)                            # multi-tenant bundle
    assert not verifier.cert_covers_brand({"san": ["gi-de.cn"], "san_count": 1, "subject_cn": "gi-de.cn"}, ALLOW)
    assert not verifier.cert_covers_brand(None, ALLOW)


def test_bulk_uses_supplied_dns_for_ownership():
    dns = {"gi-de.cn": {"status": "resolves", "a": ["203.0.113.4"], "aaaa": [], "mx": [], "ns": ["ns1.gi-de.com"]}}
    row = bulk.evaluate_domains(BRAND, KEYWORDS, ["gi-de.cn"], allowlist=ALLOW, dns=dns, include_benign=True)["results"][0]
    assert row["verdict"] == "brand_owned" and row["classification"] == "Benign/Unrelated" and row["ownership"]


# --------------------------------------------------------------------------- Google Safe Browsing
def test_safebrowsing_lookup_batches_maps_and_caches(monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_KEY", "AIza_test_key_123456")
    hosts = [f"h{i}.gi-de-x.top" for i in range(300)]
    payloads = [{"matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": "https://h3.gi-de-x.top/"}},
                             {"threatType": "MALWARE", "threat": {"url": "http://h3.gi-de-x.top/"}}]}, {}]
    with mock.patch("requests.post", side_effect=[_Resp(200, p) for p in payloads]) as post:
        out = sources.safebrowsing_lookup(hosts)
        again = sources.safebrowsing_lookup(["h3.gi-de-x.top", "h4.gi-de-x.top"])
    assert post.call_count == 2                                   # 300 hosts -> 250 + 50, nothing re-asked
    assert out == {"h3.gi-de-x.top": ["MALWARE", "SOCIAL_ENGINEERING"]} and again == out
    body = post.call_args_list[0].kwargs["json"]
    assert body["client"]["clientId"] == "brand-protection-scanner"   # nothing identifying the analyst
    assert len(body["threatInfo"]["threatEntries"]) == 500
    assert "key" in post.call_args_list[0].kwargs["params"]
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_KEY")
    assert sources.safebrowsing_lookup(["x.com"]) == {}


def test_safebrowsing_listing_scores_and_confirms():
    mm = ev("gi-de-login.top")
    cands = [{"domain": "gi-de-login.top", "sources": ["crt.sh"], "match_meta": mm, "intel": [],
              "dns": {"a": ["203.0.113.8"]}, "evidence": None, "fuzzer": "ct-hostname", "rdap": {"age_days": 2}}]
    with mock.patch.object(hunter, "safebrowsing_lookup", return_value={"gi-de-login.top": ["SOCIAL_ENGINEERING"]}):
        assert hunter._enrich_safebrowsing(cands, []) == 1
    c = cands[0]
    assert "safebrowsing" in c["sources"] and c["intel"][0]["match"] == "safe_browsing"
    d = verifier.score_candidate_detailed(c)
    assert "safe_browsing" in {b["signal"] for b in d["breakdown"]}
    assert "listed by Google Safe Browsing" in d["corroboration"]
    assert domain_matcher.classify_candidate({**c, "corroboration": d["corroboration"]}, d["score"], d["verdict"]) == "Confirmed Impersonation"


def test_safebrowsing_failure_is_reported_not_fatal():
    errors: list = []
    with mock.patch.object(hunter, "safebrowsing_lookup", side_effect=sources.SourceError("HTTP 403: this key's plan does not allow the query")):
        assert hunter._enrich_safebrowsing([{"domain": "a.com", "sources": []}], errors) == 0
    assert errors and "Safe Browsing" in errors[0]


# --------------------------------------------------------------------------- OTX passive DNS
def test_otx_passive_dns_parses_dedupes_and_caches(monkeypatch):
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    data = {"passive_dns": [
        {"hostname": "gi-de.evil-root.tech", "address": "203.0.113.9", "record_type": "A", "first": "2026-11-20T00:00:00"},
        {"hostname": "gi-de.evil-root.tech", "address": "203.0.113.10", "record_type": "A"},
        {"hostname": "*.mail.evil-root.tech", "address": "203.0.113.11", "record_type": "A"},
    ]}
    with mock.patch("requests.get", return_value=_Resp(200, data)) as g:
        rows = sources.otx_passive_dns("evil-root.tech")
        sources.otx_passive_dns("evil-root.tech")
    assert g.call_count == 1 and [r["hostname"] for r in rows] == ["gi-de.evil-root.tech", "mail.evil-root.tech"]
    assert rows[0]["first"] == "2026-11-20"
    assert "X-OTX-API-KEY" not in g.call_args.kwargs["headers"]       # anonymous without a key


def test_hunt_pivots_through_passive_dns_to_sibling_subdomains():
    """CT shows one brand subdomain under evil-root.tech; passive DNS reveals a second one CT never saw."""
    brand = {"domain": BRAND, "title": "G+D", "tokens": ["gi-de", "giesecke"], "raw_keywords": KEYWORDS, "allowlist": ALLOW,
             "favicon_mmh3": set(), "favicon_sha256": set(), "any_sha256": set(), "phashes": [], "analytics": set(),
             "words": set(), "cert_org": ""}
    ct = {"hosts": {"gi-de.evil-root.tech": {"first_seen": "2026-11-24", "last_seen": "2026-11-25", "issuer": "R3", "certs": 1}}, "error": None}
    pdns = [{"hostname": "giesecke-login.evil-root.tech", "address": "203.0.113.9", "record_type": "A", "first": "", "last": ""},
            {"hostname": "mail.evil-root.tech", "address": "203.0.113.9", "record_type": "A", "first": "", "last": ""}]

    def fake_dns(hosts, **_):
        return {h: {"domain": h, "a": ["203.0.113.9"], "aaaa": [], "mx": [], "ns": [], "status": "resolves", "registered": True}
                if "evil-root" in h else {"domain": h, "a": [], "aaaa": [], "mx": [], "ns": [], "status": "nxdomain", "registered": False}
                for h in hosts}

    with ExitStack() as st:
        for m in [
            mock.patch.object(hunter.FaviconCrawler, "scan", return_value={"domain": BRAND, "resolved_url": "https://www.gi-de.com/", "reachable": True, "icons": []}),
            mock.patch.object(hunter.feeds, "match", return_value={"hits": [], "status": [], "errors": []}),
            mock.patch.dict(hunter.SEARCHERS, {k: (lambda q, **_: []) for k in list(hunter.SEARCHERS)}),
            mock.patch.object(hunter.config, "is_configured", lambda s: s in ("urlscan", "otx")),
            mock.patch.object(hunter, "extract_asset_pivots", return_value={"analytics": [], "assets": []}),
            mock.patch.object(hunter, "brand_allowlist", return_value=ALLOW),
            mock.patch.object(hunter, "build_brand_profile", return_value=brand),
            mock.patch.object(hunter, "crtsh_search", return_value=ct),
            mock.patch.object(hunter, "resolve_domains", side_effect=fake_dns),
            mock.patch.object(hunter, "verify_candidate", return_value={"http": {"status": 200}, "title": "x"}),
            mock.patch.object(hunter, "rdap_lookup", return_value=None),
            mock.patch.object(hunter, "urlscan_search", return_value=[]),
            mock.patch.object(hunter, "hackertarget_reverse_ip", return_value=[]),
            mock.patch.object(hunter, "otx_passive_dns", return_value=pdns),
        ]:
            st.enter_context(m)
        result = hunter.run_hunt(BRAND, depth="quick", extra_keywords=KEYWORDS)
    by = {c["domain"]: c for c in result["candidates"]}
    assert "giesecke-login.evil-root.tech" in by, sorted(by)
    sib = by["giesecke-login.evil-root.tech"]
    assert sib["sources"] == ["otx"] and sib["matched_keyword"] == "Giesecke" and "login" in sib["match_meta"]["context_keywords"]
    assert "mail.evil-root.tech" not in by                         # no brand in the name: not a candidate
    assert any(p["type"] == "passive_dns" for p in result["pivots"]["auto_pivots"])


# --------------------------------------------------------------------------- source availability
def test_source_health_classifies_each_probe_and_caches(monkeypatch):
    monkeypatch.setattr(health, "_cache", {"at": 0.0, "result": None})
    codes = {"duckduckgo": 202, "crt.sh": 503, "otx": 429, "wayback": 404}

    def getter(url, **kw):
        assert kw.get("stream") is True and kw.get("timeout")
        for sid, (_, u, _) in health.FREE_PROBES.items():
            if u == url:
                if sid == "bing":
                    raise health.requests.ConnectionError("boom")
                return _Resp(codes.get(sid, 200))
        raise AssertionError(url)

    out = health.check_sources(force=True, getter=getter)
    st = {f["id"]: f["status"] for f in out["free"]}
    assert st["duckduckgo"] == "challenged" and st["crt.sh"] == "degraded" and st["otx"] == "rate_limited"
    assert st["wayback"] == "down" and st["bing"] == "down" and st["urlscan"] == "up"
    assert {k["id"] for k in out["keyed"]} >= {"virustotal", "safebrowsing", "otx"}
    assert health.check_sources(getter=lambda *a, **k: 1 / 0)["cached"] is True   # served from cache, no probes


def test_source_health_endpoint(monkeypatch):
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    import app as app_module

    monkeypatch.setattr(health, "_cache", {"at": 0.0, "result": None})
    monkeypatch.setattr(health.requests, "get", lambda url, **kw: _Resp(200))
    body = TestClient(app_module.app).get("/api/sources/health").json()
    assert body["summary"]["total"] == len(health.FREE_PROBES) + 1
    weights = TestClient(app_module.app).get("/api/scoring-weights").json()
    assert "login" in weights["lure_keywords"]


# --------------------------------------------------------------------------- RapidFuzz parity
def test_rapidfuzz_and_python_edit_distance_agree():
    rng = random.Random(3)
    for _ in range(400):
        a = "".join(rng.choices("gide-ab", k=rng.randint(0, 9)))
        b = "".join(rng.choices("gide-ab", k=rng.randint(0, 9)))
        assert domain_matcher.damerau_levenshtein(a, b) == domain_matcher._osa_python(a, b), (a, b)
    assert domain_matcher.damerau_levenshtein("gide", "gied") == 1
    assert string  # keep import used for readability of the generator above
