"""Fewer false 'Potential' leads: dead feed entries become Inactive / Historical, pages that only mention the brand
become Benign, while clones, live sightings and brand-name lookalikes stay Potential (measured on a real amazon.com
hunt: Potential 492 -> 189, Confirmed unchanged)."""
from datetime import datetime, timedelta, timezone

from core.domain_matcher import INACTIVE, classify_candidate


def cand(verdict, score=57, dns="nxdomain", technique="combosquat", intel=None, sources=("phishingdb",), title="", **ev):
    evidence = {"title": title, **ev} if (title or ev) else None
    return {"domain": "x.example.com", "verdict": verdict, "score": score, "dns_status": dns, "sources": list(sources),
            "intel": intel if intel is not None else [{"source": "phishingdb", "match": "feed", "title": "", "time": ""}],
            "evidence": evidence, "original_domain": "amazon.com",
            "match_meta": {"technique_key": technique, "matched_keyword": "amazon", "keyword_strength": "strong"}}


def cls(c):
    return classify_candidate(c, c["score"], c["verdict"])


def test_dead_feed_entries_are_inactive():
    assert cls(cand("offline")) == INACTIVE                                                     # stale feed listing, NXDOMAIN
    sb = cand("offline", intel=[{"source": "phishingdb", "match": "feed"}, {"source": "safebrowsing", "match": "safe_browsing", "title": "social engineering"}])
    assert cls(sb) == INACTIVE                                                                  # reputation alone is not a sighting


def test_anything_live_or_recent_stays_a_lead():
    assert cls(cand("offline", dns="resolves")) == "Potential Impersonation"                    # still resolves
    assert cls(cand("offline", dns="timeout")) == "Potential Impersonation"                     # unknown is not dead
    assert cls(cand("offline", sources=("urlscan",), intel=[{"source": "urlscan", "match": "daily_title", "title": "Amazon Sign-In"}])) == "Potential Impersonation"
    recent = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%d")
    assert cls(cand("offline", intel=[{"source": "phishingdb", "match": "feed", "time": recent}])) == "Potential Impersonation"
    assert cls(cand("no_website", score=30)) == "Potential Impersonation"                       # an unused lookalike can still be activated


def test_confirmed_is_never_downgraded():
    c = cand("phishing", score=90)
    c["corroboration"] = ["listed in Phishing.Database", "Google Safe Browsing"]
    assert cls(c) == "Confirmed Impersonation"


def test_pages_that_only_mention_the_brand_are_benign():
    for title in ("The #1 Selling Probiotic on Amazon – Physician's Choice", "Amazon Landing Page Generator - Coupons",
                  "Skurrile Produkte bei Amazon | Skurril"):
        c = cand("live_unrelated", score=35, dns="resolves", technique="content_infrastructure", sources=("urlscan",),
                 intel=[{"source": "urlscan", "match": "daily_title"}], title=title)
        assert cls(c) == "Benign/Unrelated", title


def test_clones_and_lures_on_third_party_pages_stay_potential():
    base = dict(verdict="live_unrelated", score=35, dns="resolves", technique="content_infrastructure", sources=("urlscan",),
                intel=[{"source": "urlscan", "match": "daily_title"}])
    assert cls(cand(title="Amazon — Earth's Biggest Selection", **base)) == "Potential Impersonation"     # presents as the brand
    assert cls(cand(title="Sign in | Amazon", **base)) == "Potential Impersonation"
    assert cls(cand(title="Gift card balance", password_form=True, **base)) == "Potential Impersonation"
    assert cls(cand(title="Deals", brand_resources=3, **base)) == "Potential Impersonation"
    listed = cand(title="Deals", **{**base, "intel": [{"source": "openphish", "match": "feed"}]})
    assert cls(listed) == "Potential Impersonation"
