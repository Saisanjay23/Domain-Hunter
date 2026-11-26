"""
Detection-quality tests for the impersonation engine.

  1. Labelled corpus  -> precision / recall / false-positive rate (printed with `pytest -s`, asserted below)
  2. One test per detection technique and per false-positive guard
  3. Evidence gating: a name match alone is never "Confirmed Impersonation"
  4. Configurable score weights, score breakdown
  5. Discovery plumbing: CT cache, per-keyword coverage, VirusTotal reputation, bulk API

Everything is offline (network calls are mocked).
"""

from __future__ import annotations

import time
from unittest import mock

import pytest

from core import bulk, config, discovery, domain_matcher, hunter, scoring, sources, verifier
from core.keypool import SourceError

BRAND = "gi-de.com"
KEYWORDS = ["gi-de", "Giesecke", "Devrient", "G+D", "Giesecke+Devrient"]
ALLOW = ["gi-de.com", "giesecke-devrient.com"]

# --------------------------------------------------------------------------- labelled corpus
# NOTE: hand-built from the cases in the enhancement brief plus common near-miss English words. It measures
# regressions in THIS engine; it is not an independent benchmark of real-world traffic.
POSITIVE = {
    # exact brand / combo
    "gi-de-security.com": "combo", "gi-de-login.net": "combo", "secure-gi-de.org": "combo", "gi-de.net": "exact",
    "gi-de.xyz": "exact", "giesecke-portal.com": "combo", "devrient-login.net": "combo",
    "gieseckedevrient-security.com": "combo", "giesecke-devrient-sso.com": "combo",
    # subdomain impersonation (brand hosted under someone else's registered domain)
    "gi-de.astrobale-core.tech": "subdomain", "login.gi-de.attacker-domain.com": "subdomain",
    "gi-de-security.malicious-site.org": "subdomain", "a.b.gi-de.evil.top": "subdomain",
    "gi-de.com.attacker.net": "subdomain", "gi.de.attacker.com": "subdomain", "devrient.attacker-host.net": "subdomain",
    "giesecke.workers.dev": "subdomain",
    # typosquats
    "gi-ed.com": "typo", "gi-do.com": "typo", "gide.com": "typo", "gieseck.com": "typo", "gieseecke.com": "typo",
    "gieseckex.com": "typo", "gieseckw.com": "typo", "devrients.com": "typo", "devreint.com": "typo",
    # homographs / IDN
    "gі-dе.com": "homograph", "giеsecke.com": "homograph", "devгient.com": "homograph",
    "xn--gi-d-e-8ya.com": "idn",
}
NEGATIVE = [
    # near-miss English words
    "wide.com", "side.com", "hide.com", "glide.com", "guide.com", "gate.com", "band.com", "hand.com", "gold.com",
    "giant.com", "reddit.com", "prevent.com", "bandwidth.com", "grand-hotel.com", "good-day.com", "gdansk.pl",
    "gmd.com", "studentservices.com", "insecure.com", "deviant.com", "gideon.com", "gideons.org",
    "guided-tours.com", "gideonsjeweler.com", "goods-store.com", "gdpr-compliance.org", "developer-client.com",
    # plain unrelated
    "example.com", "dev.example.com", "mail.google.com", "www.microsoft.com", "login.paypal.com", "news.bbc.co.uk",
]
OWNED = ["gi-de.com", "www.gi-de.com", "portal.gi-de.com", "careers.giesecke-devrient.com", "giesecke-devrient.com"]


def _run_corpus():
    result = bulk.evaluate_domains(BRAND, KEYWORDS, list(POSITIVE) + NEGATIVE + OWNED, allowlist=ALLOW, include_benign=True)
    flagged = {r["domain"] for r in result["results"] if r["classification"] != "Benign/Unrelated"}
    listed = {r["domain"] for r in result["results"]}
    return result, flagged, listed


def test_corpus_precision_recall_and_false_positive_rate():
    result, flagged, _ = _run_corpus()
    normalized = lambda h: domain_matcher.normalize_host(h)  # noqa: E731  (IDN hosts come back punycode-encoded)
    pos = {normalized(h) for h in POSITIVE}
    neg = {normalized(h) for h in NEGATIVE}
    tp, fn = len(pos & flagged), pos - flagged
    fp, tn = neg & flagged, len(neg - flagged)
    precision = tp / (tp + len(fp)) if tp + len(fp) else 1.0
    recall = tp / len(pos)
    fpr = len(fp) / len(neg)
    print(f"\ncorpus: {len(pos)} impersonations, {len(neg)} unrelated, {len(OWNED)} brand-owned -> "
          f"precision {precision:.3f}  recall {recall:.3f}  false-positive rate {fpr:.3f}  (TP {tp} FN {sorted(fn)} FP {sorted(fp)} TN {tn})")
    assert not fn, f"missed impersonations: {sorted(fn)}"
    assert not fp, f"false positives: {sorted(fp)}"
    assert precision == 1.0 and recall == 1.0 and fpr == 0.0
    assert result["summary"]["own_domains"] == len(OWNED)  # the brand's own hosts never become candidates


def test_unrelated_domains_are_never_confirmed_or_potential():
    result = bulk.evaluate_domains(BRAND, KEYWORDS, NEGATIVE, allowlist=ALLOW, include_benign=True)
    assert all(r["classification"] == "Benign/Unrelated" for r in result["results"])


# --------------------------------------------------------------------------- matching techniques
def ev(host, **kw):
    return domain_matcher.evaluate_domain_match(host, BRAND, keywords=kw.pop("keywords", KEYWORDS), **kw)


def test_required_example_subdomain_is_a_candidate():
    r = ev("gi-de.astrobale-core.tech")
    assert r["registered_domain"] == "astrobale-core.tech"
    assert r["matching_subdomain"] == "gi-de" and r["matched_keyword"] == "gi-de"
    assert r["is_subdomain_impersonation"] and r["technique_key"] == "subdomain_impersonation"
    out = bulk.evaluate_domains(BRAND, KEYWORDS, ["gi-de.astrobale-core.tech"], allowlist=ALLOW)
    assert out["results"][0]["classification"] == "Potential Impersonation"  # name only: a lead, not a verdict


@pytest.mark.parametrize("host,root", [
    ("login.gi-de.attacker-domain.com", "attacker-domain.com"),
    ("a.b.c.gi-de.evil.co.uk", "evil.co.uk"),            # multi-part public suffix
    ("gi-de.evil.github.io", "evil.github.io"),           # private suffix: github.io tenants are separate owners
])
def test_nested_subdomains_use_public_suffix_list(host, root):
    r = ev(host)
    assert r["registered_domain"] == root and r["is_subdomain_impersonation"]


def test_brand_split_across_adjacent_labels():
    for host in ("gi.de.attacker.com", "login.gi.de.attacker.com"):
        r = ev(host)
        assert r["is_subdomain_impersonation"] and r["matched_keyword"] == "gi-de", host
    r = ev("giesecke.devrient.attacker.net", keywords=["Giesecke Devrient"])
    assert r["is_subdomain_impersonation"]


@pytest.mark.parametrize("host,tech", [
    ("gi-ed.com", "typosquat_transposition"), ("gieseck.com", "typosquat_omission"),
    ("gieseecke.com", "typosquat_repetition"), ("gieseckex.com", "typosquat_insertion"),
    ("gieseckw.com", "typosquat_keyboard"), ("gi-do.com", "typosquat_substitution"), ("gide.com", "hyphen_variation"),
])
def test_each_typosquat_mechanism(host, tech):
    assert ev(host)["technique_key"] == tech


@pytest.mark.parametrize("host", ["wide.com", "side.com", "hide.com", "glide.com", "deviant.com", "gate.com"])
def test_short_stem_and_dictionary_lookalikes_are_not_typosquats(host):
    """'gide' is one edit from wide/side/hide/glide, 'devrient' is two edits from 'deviant': not evidence."""
    assert ev(host)["technique_key"] in ("none", "benign_collision")


def test_hyphenated_short_stem_keeps_its_hyphen_for_typo_credit():
    assert ev("gi-d.com")["technique_key"] == "typosquat_omission"
    assert ev("gi-dee.com")["technique_key"].startswith("typosquat_")
    assert ev("gidee.com")["technique_key"] in ("none", "benign_collision")  # no hyphen anchor: too close to real words


def test_homograph_and_punycode():
    cyr = "gі-dе.com"
    for host in (cyr, cyr.encode("idna").decode()):
        r = ev(host)
        assert r["technique_key"] == "homograph_idn" and r["is_idn"] and r["mixed_script"]
    r = ev("giеsecke.com")                      # Cyrillic 'e' inside Giesecke
    assert r["matched_keyword"] == "Giesecke" and r["technique_key"] == "homograph_idn"
    assert ev("gi-de.com.attacker.net")["registered_domain"] == "attacker.net"


def test_ascii_digit_homoglyphs():
    assert ev("g1esecke.com")["matched_keyword"] == "Giesecke"
    assert ev("dev-rient.com")["matched_keyword"] == "Devrient"


def test_every_analyst_keyword_is_evaluated_independently():
    cases = {"giesecke-x.com": "Giesecke", "devrient-x.com": "Devrient", "gd-login.org": "G+D",
             "gieseckedevrient-x.com": "Giesecke+Devrient", "gi-de-x.com": "gi-de"}
    for host, kw in cases.items():
        r = ev(host)
        assert r["matched_keyword"] == kw, (host, r["matched_keyword"])
        assert kw in r["matched_keywords"]


def test_all_matching_keywords_are_recorded():
    r = ev("giesecke-devrient-login.attacker.net")
    names = {h["keyword"] for h in r["keyword_hits"]}
    assert {"Giesecke", "Devrient"} <= names


def test_weak_abbreviation_is_recorded_but_scored_low():
    r = ev("gd.attacker-host.net")
    assert r["matched_keyword"] == "G+D" and r["keyword_strength"] == "weak"
    assert r["is_subdomain_impersonation"] and not r["is_benign_collision"]   # was contradictory before
    assert any("abbreviation" in x for x in r["match_reasons"])
    name_only = bulk.evaluate_domains(BRAND, KEYWORDS, ["gd.attacker-host.net"], allowlist=ALLOW, include_benign=True)["results"][0]
    assert name_only["score"] < 35 and name_only["classification"] == "Benign/Unrelated"
    # ...but corroborating signals (registered 3 days ago, mail + web) lift it into review
    cand = {"domain": "gd.attacker-host.net", "fuzzer": "brand-subdomain", "sources": ["crt.sh"], "match_meta": r,
            "dns": {"a": ["203.0.113.9"], "aaaa": [], "mx": ["mx.x.net"], "ns": []}, "rdap": {"age_days": 3}, "evidence": {"http": {"status": 200}}}
    score, verdict, _ = verifier.score_candidate(cand)
    assert score >= 35 and domain_matcher.classify_candidate(cand, score, verdict) == "Potential Impersonation"


def test_legitimate_and_owned_domains_are_not_flagged():
    for host in OWNED:
        r = ev(host, allowlist=ALLOW)
        assert r["is_own_domain"] and not r["is_subdomain_impersonation"]


def test_keyword_expansion_does_not_invent_noise_forms():
    forms = {f for s in domain_matcher.expand_analyst_keywords(BRAND, KEYWORDS) for f in s["forms"]}
    assert "gnd" not in forms and "gandd" not in forms         # old expansion of "G+D"
    assert "gieseckeanddevrient" in forms


def test_keyword_search_tokens_cover_every_keyword_before_repeating_any():
    specs = domain_matcher.expand_analyst_keywords(BRAND, KEYWORDS)
    toks = domain_matcher.keyword_search_tokens(specs, min_len=4, limit=5)
    assert {"gi-de", "giesecke", "devrient"} <= set(toks)            # a plain "first 5 forms" cut dropped some of these
    assert any(t.startswith("giesecke") and "devrient" in t for t in toks)   # the combined brand name too
    assert len(domain_matcher.keyword_search_tokens(specs, limit=3)) == 3


def test_match_results_are_independent_copies():
    a = ev("gi-de.astrobale-core.tech")
    a["matched_keyword"] = "tampered"
    assert ev("gi-de.astrobale-core.tech")["matched_keyword"] == "gi-de"


# --------------------------------------------------------------------------- evidence gating & scoring
def _subdomain_candidate(**over):
    mm = ev("gi-de.astrobale-core.tech")
    cand = {"domain": "gi-de.astrobale-core.tech", "fuzzer": "brand-subdomain", "sources": ["crt.sh"], "match_meta": mm,
            "dns": {"a": ["203.0.113.5"], "aaaa": [], "mx": ["mx.evil.tech"], "ns": []}, "dns_status": "resolves",
            "rdap": {"age_days": 3}, "evidence": {"http": {"status": 200}, "title": "Welcome"}}
    cand.update(over)
    return cand


def test_name_and_registration_alone_never_confirm():
    cand = _subdomain_candidate()
    d = verifier.score_candidate_detailed(cand)
    assert d["raw_total"] >= 70, "setup: signals should add up to a high raw score"
    assert d["capped"] and d["score"] <= 69 and d["verdict"] == "suspicious"
    assert d["corroboration"] == []
    assert domain_matcher.classify_candidate(cand, d["score"], d["verdict"]) == "Potential Impersonation"
    assert any("capped" in r for r in d["reasons"])


@pytest.mark.parametrize("evidence_patch,intel", [
    ({"favicon": {"exact_match": True}}, None),
    ({"brand_in_title": True}, None),
    ({"shared_analytics": ["UA-1"]}, None),
    ({"visual_distance": 4}, None),
    ({}, [{"source": "openphish", "match": "feed"}]),
    ({}, [{"source": "virustotal", "match": "reputation", "malicious_votes": 5}]),
])
def test_independent_evidence_confirms(evidence_patch, intel):
    cand = _subdomain_candidate()
    cand["evidence"] = {**cand["evidence"], **evidence_patch}
    if intel:
        cand["intel"] = intel
    d = verifier.score_candidate_detailed(cand)
    assert d["corroboration"] and not d["capped"]
    assert d["score"] >= 70 and d["verdict"] == "phishing"
    assert domain_matcher.classify_candidate(cand, d["score"], d["verdict"]) == "Confirmed Impersonation"


def test_virustotal_vendor_count_is_graded():
    base = _subdomain_candidate(dns={"a": [], "aaaa": [], "mx": [], "ns": []}, rdap=None, evidence=None)
    one = verifier.score_candidate_detailed({**base, "intel": [{"source": "virustotal", "match": "reputation", "malicious_votes": 1}]})
    many = verifier.score_candidate_detailed({**base, "intel": [{"source": "virustotal", "match": "reputation", "malicious_votes": 6}]})
    assert {b["signal"] for b in one["breakdown"]} >= {"vt_suspicious"} and many["score"] > one["score"]
    assert "vt_malicious" in {b["signal"] for b in many["breakdown"]}
    assert one["corroboration"] == []          # a single vendor is not corroboration
    assert many["corroboration"]


def test_breakdown_sums_to_score_and_explains_each_signal():
    cand = _subdomain_candidate(evidence={"http": {"status": 200}, "favicon": {"exact_match": True}, "password_form": True})
    d = verifier.score_candidate_detailed(cand)
    assert sum(b["points"] for b in d["breakdown"]) == min(100, d["raw_total"]) == d["score"] or d["score"] == 100
    assert all(b["signal"] and b["reason"] for b in d["breakdown"])
    assert {"subdomain_impersonation", "favicon_exact"} <= {b["signal"] for b in d["breakdown"]}
    assert verifier.score_candidate(cand)[:2] == (d["score"], d["verdict"])          # wrapper stays in sync


def test_score_weights_are_configurable(monkeypatch):
    cand = _subdomain_candidate(evidence=None)
    monkeypatch.delenv("THREAT_SCORE_WEIGHTS", raising=False)
    base = verifier.score_candidate_detailed(cand)
    monkeypatch.setenv("THREAT_SCORE_WEIGHTS", '{"age_30": 25, "subdomain_impersonation": 10, "bogus": 5}')
    tuned = verifier.score_candidate_detailed(cand)
    by = {b["signal"]: b["points"] for b in tuned["breakdown"]}
    assert by["age_30"] == 25 and by["subdomain_impersonation"] == 10
    assert tuned["raw_total"] == base["raw_total"] + (25 - 18) + (10 - 32)
    assert "bogus" not in scoring.get_weights()[0]


def test_invalid_weight_config_falls_back_to_defaults(monkeypatch):
    monkeypatch.setenv("THREAT_SCORE_WEIGHTS", "{not json")
    assert scoring.get_weights()[0] == scoring.DEFAULT_WEIGHTS
    monkeypatch.setenv("THREAT_SCORE_WEIGHTS", '{"age_30": 9000, "feed": "lots", "thresholds": {"phishing": 80, "x": 1}}')
    w, t = scoring.get_weights()
    assert w["age_30"] == scoring.DEFAULT_WEIGHTS["age_30"] and w["feed"] == scoring.DEFAULT_WEIGHTS["feed"]
    assert t["phishing"] == 80 and "x" not in t


def test_phishing_threshold_is_configurable(monkeypatch):
    cand = _subdomain_candidate()
    cand["evidence"] = {**cand["evidence"], "brand_in_title": True}
    monkeypatch.setenv("THREAT_SCORE_WEIGHTS", '{"thresholds": {"phishing": 95}}')
    assert verifier.score_candidate_detailed(cand)["verdict"] == "suspicious"


# --------------------------------------------------------------------------- discovery plumbing
class _Resp:
    def __init__(self, status=200, data=None, headers=None):
        self.status_code, self._data, self.headers, self.text = status, data, headers or {}, ""

    def json(self):
        if self._data is None:
            raise ValueError("no json")
        return self._data


def test_ct_lookups_are_cached_and_failures_are_not():
    rows = [{"name_value": "gi-de.astrobale-core.tech", "not_before": "2026-11-24T00:00:00", "issuer_name": 'O="Let\'s Encrypt"'}]
    with mock.patch("requests.get", return_value=_Resp(200, rows)) as g:
        first = discovery.crtsh_search("gi-de", retries=0)
        second = discovery.crtsh_search("gi-de", retries=0)
    assert g.call_count == 1 and "gi-de.astrobale-core.tech" in first["hosts"] and second.get("cached")
    second["hosts"].clear()                                    # callers cannot corrupt the cache
    with mock.patch("requests.get") as g:
        assert discovery.crtsh_search("gi-de", retries=0)["hosts"]
        assert g.call_count == 0

    discovery.clear_ct_cache()
    with mock.patch("requests.get", return_value=_Resp(503)) as g, mock.patch.object(discovery, "_ctlogs_fallback", return_value=None):
        assert discovery.crtsh_search("devrient", retries=0)["error"]
        discovery.crtsh_search("devrient", retries=0)
    assert g.call_count == 2                                   # errors are retried, never served from cache


def test_ct_rate_limit_backs_off(monkeypatch):
    slept = []
    monkeypatch.setattr(discovery.time, "sleep", slept.append)
    with mock.patch("requests.get", return_value=_Resp(429, headers={"Retry-After": "4"})), \
            mock.patch.object(discovery, "_ctlogs_fallback", return_value=None):
        out = discovery.crtsh_search("giesecke", retries=1)
    assert out["error"] and slept and slept[0] >= 4


def _vt_obj(mal=0, susp=0):
    return {"data": {"type": "domain", "id": "gi-de.astrobale-core.tech",
                     "attributes": {"last_analysis_stats": {"malicious": mal, "suspicious": susp},
                                    "categories": {"x": "phishing", "y": "phishing"}}}}


def test_virustotal_reputation_lookup(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt_test_key_1234")
    with mock.patch("requests.get", return_value=_Resp(200, _vt_obj(7, 1))) as g:
        hit = sources.virustotal_reputation("gi-de.astrobale-core.tech")
        again = sources.virustotal_reputation("gi-de.astrobale-core.tech")
    assert hit["malicious_votes"] == 7 and hit["categories"] == ["phishing"] and again == hit and g.call_count == 1
    with mock.patch("requests.get", return_value=_Resp(404, {"error": {"message": "not found"}})):
        assert sources.virustotal_reputation("never-seen.example") is None
    monkeypatch.delenv("VIRUSTOTAL_API_KEY")
    assert sources.virustotal_reputation("no-key.example") is None


def test_hunt_enrichment_adds_vendor_flags_only_and_stops_on_rate_limit():
    def cand(domain, score):
        return {"domain": domain, "sources": ["crt.sh"], "score": score, "intel": [],
                "match_meta": ev(domain)}
    flagged, clean, third = cand("gi-de.a-evil.top", 60), cand("giesecke-x.com", 50), cand("devrient-x.net", 40)
    answers = iter([{"malicious_votes": 6, "suspicious_votes": 0, "title": "VT flagged (6 malicious)", "url": "https://vt/x"},
                    {"malicious_votes": 0, "suspicious_votes": 0}, SourceError("HTTP 429: rate limited", kind="rate_limit")])

    def fake(host):
        a = next(answers)
        if isinstance(a, Exception):
            raise a
        return a

    errors: list = []
    with mock.patch.object(hunter, "virustotal_reputation", side_effect=fake):
        n = hunter._enrich_virustotal([clean, third, flagged], errors, lambda *a: None)
    assert n == 2 and flagged["intel"][0]["malicious_votes"] == 6 and flagged["intel"][0]["match"] == "reputation"
    assert clean["intel"] == [] and third["intel"] == []          # no detections: no evidence either way
    assert errors and "rate limited" in errors[0]                 # surfaced, hunt carried on


def _hunt_mocks(ct_calls, brand_kw=KEYWORDS):
    brand = {"domain": BRAND, "title": "G+D", "tokens": ["gi-de", "giesecke", "devrient"], "raw_keywords": brand_kw,
             "allowlist": ALLOW, "favicon_mmh3": set(), "favicon_sha256": set(), "any_sha256": set(), "phashes": [],
             "analytics": set(), "words": set(), "cert_org": ""}

    def fake_ct(tok, **_):
        ct_calls.append(tok)
        return {"hosts": {}, "error": None}

    return [
        mock.patch.object(hunter.FaviconCrawler, "scan", return_value={"domain": BRAND, "resolved_url": "https://www.gi-de.com/", "reachable": True, "icons": []}),
        mock.patch.object(hunter.feeds, "match", return_value={"hits": [], "status": [], "errors": []}),
        mock.patch.object(hunter, "run_intel", return_value={"hits": [], "status": []}),
        mock.patch.object(hunter, "extract_asset_pivots", return_value={"analytics": [], "assets": []}),
        mock.patch.object(hunter, "brand_allowlist", return_value=ALLOW),
        mock.patch.object(hunter, "build_brand_profile", return_value=brand),
        mock.patch.object(hunter, "crtsh_search", side_effect=fake_ct),
        mock.patch.object(hunter, "resolve_domains", return_value={}),
        mock.patch.object(hunter, "rdap_lookup", return_value=None),
    ]


def test_hunt_searches_ct_for_every_analyst_keyword():
    calls: list = []
    kws = ["gi-de", "Giesecke", "Devrient", "Acme Holdings", "Globex", "Initech"]
    from contextlib import ExitStack
    with ExitStack() as st:
        for m in _hunt_mocks(calls, kws):
            st.enter_context(m)
        hunter.run_hunt(BRAND, depth="quick", extra_keywords=kws)
    joined = " ".join(calls)
    for needle in ("gi-de", "giesecke", "devrient", "acme", "globex", "initech"):
        assert needle in joined, f"CT was never searched for '{needle}': {calls}"


def test_intel_plan_mentions_every_keyword_token():
    from core import pivots
    toks = ["gi-de", "giesecke", "devrient", "acme-holdings", "globex", "initech"]
    plan = pivots.build_intel_plan({}, [], {"analytics": [], "assets": []}, {}, ALLOW, "gi-de", toks)
    text = " ".join(p["query"] for p in plan)
    for t in toks[:5]:
        assert t in text, f"{t} missing from intel plan"


# --------------------------------------------------------------------------- bulk engine & API
def test_bulk_dedup_merges_sources_and_counts_noise():
    out = bulk.evaluate_domains(BRAND, KEYWORDS, [
        {"domain": "gi-de.astrobale-core.tech", "source": "crt.sh"}, {"domain": "GI-DE.astrobale-core.tech.", "source": "urlscan"},
        "https://gi-de.astrobale-core.tech/login", "not a domain", "", "portal.gi-de.com", "wide.com",
    ], allowlist=ALLOW)
    s = out["summary"]
    assert s["unique"] == 3 and s["duplicates"] == 2 and s["invalid"] == 2 and s["own_domains"] == 1
    (row,) = out["results"]
    assert set(row["sources"]) == {"crt.sh", "urlscan", "input"}


def test_bulk_domain_without_dns_is_a_lead_never_confirmed():
    dns = {"gi-de.astrobale-core.tech": {"status": "nxdomain", "a": [], "aaaa": [], "mx": [], "ns": []}}
    row = bulk.evaluate_domains(BRAND, KEYWORDS, ["gi-de.astrobale-core.tech"], allowlist=ALLOW, dns=dns)["results"][0]
    assert row["classification"] == "Potential Impersonation" and row["dns_status"] == "nxdomain"
    assert row["verdict"] == "no_website" and row["score"] <= 40


def test_large_lists_are_fast_and_exact():
    import random
    import string
    rng = random.Random(7)
    noise = ["".join(rng.choices(string.ascii_lowercase, k=rng.randint(7, 15))) + rng.choice([".com", ".net", ".co.uk", ".io"]) for _ in range(8000)]
    hosts = noise + [f"x{i}.gi-de.t{i}.xyz" for i in range(50)] + noise[:2000]          # 2,000 duplicates
    t0 = time.perf_counter()
    out = bulk.evaluate_domains(BRAND, KEYWORDS, hosts, allowlist=ALLOW)
    elapsed = time.perf_counter() - t0
    assert out["summary"]["duplicates"] == 2000
    assert sum(1 for r in out["results"] if r["technique_key"] == "subdomain_impersonation") == 50
    assert elapsed < 20, f"10k hosts took {elapsed:.1f}s"


def _client():
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    import app as app_module
    return TestClient(app_module.app)


def test_evaluate_endpoint():
    c = _client()
    r = c.post("/api/impersonation/evaluate", json={
        "original_domain": BRAND, "keywords": KEYWORDS, "allowlist": ALLOW,
        "domains": ["gi-de.astrobale-core.tech", "wide.com", "gi-ed.com", "portal.gi-de.com"],
    })
    assert r.status_code == 200
    body = r.json()
    assert [x["domain"] for x in body["results"]] == ["gi-de.astrobale-core.tech", "gi-ed.com"] or \
        {x["domain"] for x in body["results"]} == {"gi-de.astrobale-core.tech", "gi-ed.com"}
    top = next(x for x in body["results"] if x["domain"] == "gi-de.astrobale-core.tech")
    assert top["registered_domain"] == "astrobale-core.tech" and top["matching_subdomain"] == "gi-de"
    assert top["score_breakdown"] and top["match_reasons"]
    assert c.post("/api/impersonation/evaluate", json={"original_domain": BRAND, "domains": []}).status_code == 400
    assert c.post("/api/impersonation/evaluate", json={"original_domain": " ", "domains": ["a.com"]}).status_code == 400
    assert c.post("/api/impersonation/evaluate", json={"original_domain": BRAND, "domains": ["a.com"]},
                  headers={"Origin": "http://evil.example", "Host": "127.0.0.1:8080"}).status_code == 403


def test_scoring_weights_endpoint():
    body = _client().get("/api/scoring-weights").json()
    assert body["weights"]["subdomain_impersonation"] == 32 and body["thresholds"]["phishing"] == 70
    assert config  # silence unused import in minimal environments


# --------------------------------------------------------------------------- plan limits & anti-bot skips
def test_urlscan_keyword_queries_use_no_leading_wildcard():
    from core import pivots
    plan = pivots.build_intel_plan({}, [], {"analytics": [], "assets": []}, {}, ALLOW, "gi-de",
                                   ["gi-de", "gide", "giesecke", "devrient", "gieseckedevrient"])
    kw = [p for p in plan if p["label"].startswith("Keyword '")]
    assert kw, "per-keyword URLScan queries should exist"
    assert all(":*" not in p["query"] for p in kw), [p["query"] for p in kw]


def _run_intel_with(monkeypatch, searchers, plan):
    monkeypatch.setenv("FREE_ONLY_MODE", "0")  # these tests exercise paid-platform plan limits
    monkeypatch.setattr(hunter, "SEARCHERS", searchers)
    monkeypatch.setattr(hunter.config, "is_configured", lambda s: True)
    return hunter.run_intel(plan, [])


def test_forbidden_urlscan_wildcard_query_is_retried_without_the_wildcard(monkeypatch):
    seen = []

    def urlscan(q, **_):
        seen.append(q)
        if ":*" in q:
            raise SourceError("HTTP 403: this key's plan does not allow the query", kind="forbidden")
        return [{"host": "gide.evil.top", "source": "urlscan"}]

    out = _run_intel_with(monkeypatch, {"urlscan": urlscan},
                          [{"source": "urlscan", "match": "dork", "label": "x", "query": "page.domain:*gide*"}])
    assert seen == ["page.domain:*gide*", "page.domain:gide*"]
    assert out["status"][0]["error"] is None and out["hits"][0]["host"] == "gide.evil.top"


def test_fofa_plan_rejection_falls_back_to_the_cheaper_query(monkeypatch):
    calls = []

    def fofa(q, **_):
        calls.append(q)
        if q == "MASTER":
            raise SourceError("key failed, last error: FOFA: your FOFA plan does not allow this query (code 820001)", kind="exhausted")
        return [{"host": "gide-login.top", "source": "fofa"}]

    plan = [{"source": "fofa", "match": "dork", "label": "x", "query": "MASTER", "fallback": 'host="gide"'}]
    out = _run_intel_with(monkeypatch, {"fofa": fofa}, plan)
    assert calls == ["MASTER", 'host="gide"'] and out["hits"]


def test_plan_limits_and_challenges_are_skipped_not_reported_as_errors(monkeypatch):
    def fofa(q, **_):
        raise SourceError("key failed, last error: FOFA: your FOFA plan does not allow this query (code 820001)", kind="exhausted")

    def ddg(q, **_):
        raise SourceError("DuckDuckGo HTML search challenged (skipping cleanly; Bing RSS / URLScan still active)", kind="rate")

    def broken(q, **_):
        raise SourceError("HTTP 500")

    plan = [{"source": "fofa", "match": "favicon_hash", "label": "fav", "query": "icon_hash=1"},
            {"source": "duckduckgo", "match": "dork", "label": "ddg", "query": "q"},
            {"source": "urlscan", "match": "dork", "label": "real failure", "query": "q"}]
    out = _run_intel_with(monkeypatch, {"fofa": fofa, "duckduckgo": ddg, "urlscan": broken}, plan)
    by = {s["label"]: s for s in out["status"]}
    assert by["fav"]["skipped"] and by["ddg"]["skipped"]
    assert not by["real failure"].get("skipped")          # genuine failures are still surfaced
