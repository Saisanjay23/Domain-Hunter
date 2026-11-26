"""
Free-only mode (the default) and the Settings > Source activity log that replaces warnings on the results screens.
"""

from __future__ import annotations

from unittest import mock

import pytest

from core import config, hunter, pivots, source_events, sources

# The four warnings an analyst saw on the hunt screen before this change.
REPORTED = [
    "URLScan 'Keyword 'gide': subdomain & host clones': HTTP 403: this key's plan does not allow the query",
    "DuckDuckGo 'DuckDuckGo search: gi-de mentions outside official site': DuckDuckGo HTML search challenged (skipping cleanly; Bing RSS / URLScan still active)",
    "FOFA 'Servers serving the brand favicon': key failed, last error: FOFA: your FOFA plan does not allow this query (code 820001)",
    "FOFA 'Lookalike titles / hosts / certs': key failed, last error: FOFA: your FOFA plan does not allow this query (code 820001)",
]


@pytest.fixture
def paid_keys(monkeypatch):
    for name in ("SHODAN_API_KEY", "FOFA_KEY", "CENSYS_PAT", "SERPAPI_KEY", "WHOISXML_API_KEY", "URLSCAN_API_KEY"):
        monkeypatch.setenv(name, f"test-key-{name.lower()}-123456")
    monkeypatch.delenv("FREE_ONLY_MODE", raising=False)


def test_free_mode_is_the_default_and_switches_paid_sources_off(paid_keys, monkeypatch):
    assert config.free_only()
    for paid in ("shodan", "fofa", "censys", "serpapi", "whoisxml"):
        assert config.is_configured(paid) and not config.is_enabled(paid), paid
    for free in ("urlscan", "bing", "duckduckgo", "wayback", "crt.sh"):
        assert config.is_enabled(free), free
    st = {s["id"]: s for s in config.sources_status()}
    assert st["fofa"]["mode"] == "free_mode_off" and not st["fofa"]["enabled"] and st["fofa"]["paid"]
    monkeypatch.setenv("FREE_ONLY_MODE", "0")
    assert config.is_enabled("fofa")


def test_intel_plan_has_no_paid_or_pro_only_queries_in_free_mode(paid_keys):
    plan = pivots.build_intel_plan({"shodan": "http.favicon.hash:1", "fofa": 'icon_hash="1"', "censys": "x"}, [], {"analytics": ["UA-1-1"], "assets": []},
                                   {"fofa": {"master": "M"}, "shodan": {"title_spoof": "T"}, "censys": {"master": "C"},
                                    "urlscan": {"all_domains": "page.domain.keyword:*gide*"}}, ["gi-de.com"], "gi-de",
                                   ["gi-de", "gide", "giesecke"])
    srcs = {p["source"] for p in plan}
    assert not srcs & {"shodan", "fofa", "censys", "whoisxml", "serpapi"}, srcs
    assert not any("All domains containing brand" in p["label"] for p in plan)
    assert not any(":*" in p["query"] for p in plan if p["source"] == "urlscan")


@pytest.mark.parametrize("query,expected", [
    ("page.domain.keyword:*gide*", "page.domain:gide*"),
    ("(page.domain:*giesecke* OR page.title:\"G+D\")", "(page.domain:giesecke* OR page.title:\"G+D\")"),
    ("page.domain:gide*", "page.domain:gide*"),
    ("hash:abc123 AND date:>now-24h", "hash:abc123 AND date:>now-24h"),
])
def test_urlscan_queries_are_made_free_plan_safe(query, expected, monkeypatch):
    monkeypatch.delenv("FREE_ONLY_MODE", raising=False)
    assert sources.urlscan_free_safe(query) == expected
    monkeypatch.setenv("FREE_ONLY_MODE", "0")
    assert sources.urlscan_free_safe(query) == query


def test_urlscan_search_sends_the_safe_query(monkeypatch):
    monkeypatch.delenv("FREE_ONLY_MODE", raising=False)
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    seen = []

    class R:
        status_code = 200
        headers = {}

        def json(self):
            return {"results": []}

    with mock.patch("requests.get", side_effect=lambda url, params=None, **kw: seen.append(params["q"]) or R()):
        sources.urlscan_search("page.domain.keyword:*gide*")
    assert seen == ["page.domain:gide*"]


def test_run_intel_never_calls_paid_sources_in_free_mode(paid_keys, monkeypatch):
    called = []
    monkeypatch.setattr(hunter, "SEARCHERS", {k: (lambda q, k=k, **kw: called.append(k) or []) for k in ("fofa", "shodan", "censys", "urlscan")})
    plan = [{"source": "fofa", "match": "favicon_hash", "label": "Servers serving the brand favicon", "query": "icon_hash=1"},
            {"source": "shodan", "match": "dork", "label": "t", "query": "q"},
            {"source": "urlscan", "match": "dork", "label": "u", "query": "page.domain:gide*"}]
    out = hunter.run_intel(plan, ["https://img/logo.png"])
    assert called == ["urlscan"]
    assert [s["source"] for s in out["status"]] == ["urlscan"]          # nothing about the paid ones: no noise


def test_reported_warnings_are_classified_for_the_settings_log():
    source_events.record_many(REPORTED, "Brand Hunt", target="gi-de.com")
    s = source_events.summary()
    by = {x["source"]: x for x in s["sources"]}
    assert set(by) == {"urlscan", "duckduckgo", "fofa"}
    assert by["fofa"]["count"] == 2 and by["fofa"]["latest"]["kind"] == "plan"
    assert by["urlscan"]["latest"]["kind"] == "plan" and by["urlscan"]["latest"]["label"] == "Keyword 'gide': subdomain & host clones"
    assert by["duckduckgo"]["latest"]["kind"] == "challenge"
    assert all(x["advice"] for x in s["sources"]) and s["events"][0]["context"] == "Brand Hunt"
    source_events.clear("fofa")
    assert {x["source"] for x in source_events.summary()["sources"]} == {"urlscan", "duckduckgo"}
    source_events.clear()
    assert source_events.summary()["sources"] == []


def test_log_survives_a_restart(tmp_path):
    path = str(tmp_path / "events.json")
    source_events._reset_for_tests(path)
    source_events.record("OTX passive DNS", "HTTP 429: rate limited", "Infrastructure")
    source_events._reset_for_tests(path)
    source_events._LOADED = False                                       # simulate a fresh process reading the file
    assert source_events.summary()["sources"][0]["source"] == "otx"


def test_events_and_settings_api(paid_keys):
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    import app as app_module

    source_events.record_many(REPORTED[2:], "Brand Hunt")
    c = TestClient(app_module.app)
    body = c.get("/api/sources/events").json()
    assert body["free_only"] is True and "FOFA" in body["paid_sources"]
    assert body["sources"][0]["source"] == "fofa"
    from api.routes.settings import settings_payload  # the endpoint itself only answers localhost

    src = {s["id"]: s for s in settings_payload()["sources"]}
    assert src["fofa"]["free_mode_off"] and src["fofa"]["paid"] and not src["urlscan"]["free_mode_off"]
    assert c.delete("/api/sources/events").status_code == 403                  # clearing the log is localhost-only
    with mock.patch.multiple(app_module, SETTINGS_ALLOWED_CLIENTS={"testclient"}, SETTINGS_ALLOWED_HOSTS={"testserver"}):
        assert c.delete("/api/sources/events").status_code == 200
    assert c.get("/api/sources/events").json()["sources"] == []
