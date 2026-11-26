"""Offline tests for URLScan daily search (page.domain + page.title), WhoisXML integration, and UI parity."""

import json
import os
import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

import app as app_module
from core import config, daily_intel, discovery, dorks, impersonation, pivots, sources, verifier


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("", encoding="utf-8")
    monkeypatch.setattr(config, "ENV_FILE", str(env_file))
    for var in (
        "WHOISXML_API_KEY",
        "URLSCAN_API_KEY",
        "SHODAN_API_KEY",
        "FOFA_KEY",
        "FOFA_EMAIL",
        "CENSYS_PAT",
        "CENSYS_ORG_ID",
        "SERPAPI_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(config, "_loaded_mtime", None)
    config._from_file.clear()
    with sources.POOL._lock:
        sources.POOL._state.clear()
    yield env_file
    for var in (
        "WHOISXML_API_KEY",
        "URLSCAN_API_KEY",
        "SHODAN_API_KEY",
        "FOFA_KEY",
        "FOFA_EMAIL",
        "CENSYS_PAT",
        "CENSYS_ORG_ID",
        "SERPAPI_KEY",
    ):
        os.environ.pop(var, None)
    config._from_file.clear()
    config._loaded_mtime = None
    with sources.POOL._lock:
        sources.POOL._state.clear()


def _mock_response(status_code=200, payload=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = payload if payload is not None else {}
    resp.text = json.dumps(payload or {})
    return resp


class TestDailyAndRefactoredUI:
    def test_index_has_hero_daily_radar_and_modular_assets(self):
        with TestClient(app_module.app) as client:
            r = client.get("/")
            assert r.status_code == 200
            html = r.text
            assert "/static/css/tokens.css" in html
            assert "/static/css/animations.css" in html
            assert "/static/css/main.css" in html
            assert "/static/js/daily.js" in html
            assert "/static/js/hunt.js" in html

            soup = BeautifulSoup(html, "html.parser")
            assert "Domain Hunter" in html
            assert "Sai Sanjay" in html
            app_root = soup.find(id="app")
            assert app_root is not None
            # The navigation rail is always visible now (no "landing" state); the new shell assets must be linked.
            assert "landing" not in (app_root.get("class") or [])
            for asset in ("/static/css/shell.css", "/static/css/components.css", "/static/css/overview.css", "/static/css/landing.css", "/static/js/shell.js"):
                assert asset in html
            main = soup.find("main", id="content")
            assert main is not None
            direct_ids = {child.get("id") for child in main.find_all(recursive=False) if child.get("id")}
            assert {"overview-page", "daily-scan-form", "daily-results-section", "hunt-scan-form", "hunt-progress-panel", "hunt-results-section"} <= direct_ids
            assert soup.find(id="hunt-donut-card") is not None
            assert soup.find(id="hunt-platform-spotlight") is not None
            assert soup.find(id="hunt-rail-sources") is not None

            for asset in (
                "/favicon.ico",
                "/static/assets/favicon.svg",
                "/static/assets/favicon-32x32.png",
                "/static/assets/apple-touch-icon.png",
                "/static/css/tokens.css",
                "/static/css/animations.css",
                "/static/css/main.css",
                "/static/css/landing.css",
                "/static/js/backdrop.js",
                "/static/js/api.js",
                "/static/js/scanner.js",
                "/static/js/daily.js",
                "/static/js/hunt.js",
                "/static/js/dorks.js",
                "/static/js/cases.js",
                "/static/js/settings.js",
                "/static/js/app.js",
                "/static/assets/brand-shield-hero.svg",
                "/static/assets/landing-hacker-body.png",
                "/static/assets/landing-hacker-body.webp",
                "/static/assets/landing-hacker-fingers.png",
                "/static/assets/landing-hacker-fingers.webp",
            ):
                assert client.get(asset).status_code == 200, asset

            landing = soup.find(id="landing-page")
            assert landing is not None
            assert soup.find(id="landing-search-form") is not None
            assert soup.find(id="landing-domain-input") is not None
            assert soup.find(id="btn-landing-hunt") is not None
            assert soup.find(id="landing-error") is not None
            assert landing.select_one(".dh-char-body") is not None
            assert landing.select_one(".dh-char-fingers") is not None

            assert soup.find(id="hunt-brand-snapshot") is not None
            assert soup.find(id="hunt-brand-avatar") is not None

            # Obsolete monolithic UI files were cleanly removed.
            assert client.get("/static/style.css").status_code == 404
            assert client.get("/static/app.js").status_code == 404

    def test_every_js_dom_id_exists_in_html(self):
        static_dir = Path(app_module.__file__).resolve().parent / "web" / "static"
        soup = BeautifulSoup((static_dir / "index.html").read_text(encoding="utf-8"), "html.parser")
        html_ids = {el.get("id") for el in soup.find_all(id=True)}

        referenced_ids = set()
        rendered_ids = set()   # ids of elements the scripts render themselves (id="..." inside template strings)
        for js_file in (static_dir / "js").glob("*.js"):
            src = js_file.read_text(encoding="utf-8")
            referenced_ids.update(re.findall(r'getElementById\("([A-Za-z0-9_-]+)"\)', src))
            rendered_ids.update(re.findall(r'\bid="([A-Za-z0-9_-]+)"', src))

        missing = sorted(referenced_ids - html_ids - rendered_ids)
        assert missing == []

    def test_redesigned_enterprise_sidebar_filters_and_safe_open_domain(self):
        static_dir = Path(app_module.__file__).resolve().parent / "web" / "static"
        html = (static_dir / "index.html").read_text(encoding="utf-8")
        soup = BeautifulSoup(html, "html.parser")

        # Interactive collapsible sidebar + tooltips
        assert soup.find(id="btn-sidebar-toggle") is not None
        nav_items = soup.select(".sidebar .nav-item[data-tab]")
        assert len(nav_items) >= 9
        assert all(item.get("data-tooltip") for item in nav_items)

        # Visible optional Daily keywords, analytics charts, multi-facet filters, and pagination
        for expected_id in (
            "daily-keywords",
            "hunt-analytics-charts",
            "daily-analytics-charts",
            "hunt-min-score",
            "hunt-source-filter",
            "hunt-technique-filter",
            "daily-class-filter",
            "daily-technique-filter",
            "hunt-pagination",
            "daily-pagination",
        ):
            assert soup.find(id=expected_id) is not None, expected_id

        # Safe external opening & dynamic explanations present across shared helpers and views
        api_js = (static_dir / "js" / "api.js").read_text(encoding="utf-8")
        hunt_js = (static_dir / "js" / "hunt.js").read_text(encoding="utf-8")
        daily_js = (static_dir / "js" / "daily.js").read_text(encoding="utf-8")
        dorks_js = (static_dir / "js" / "dorks.js").read_text(encoding="utf-8")
        assert 'rel="noopener noreferrer"' in api_js
        assert "Open Domain ↗" in api_js
        assert "buildDetectionExplanation" in hunt_js and "buildDetectionExplanation" in daily_js
        assert "openDomainBtn(" in hunt_js and "openDomainBtn(" in daily_js and "openDomainBtn(" in dorks_js

        # Regression guard against finding-card column squishing
        css = (static_dir / "css" / "main.css").read_text(encoding="utf-8")
        assert "sidebar-collapsed" in css
        assert ".finding-card-top" in css

    def test_frontend_render_functions_execute_without_runtime_errors(self):
        import shutil
        import subprocess

        node = shutil.which("node")
        if not node:
            pytest.skip("node not installed")
        static_dir = Path(app_module.__file__).resolve().parent / "web" / "static"
        script = f"""
        const fs = require('fs');
        const vm = require('vm');
        const path = require('path');
        const jsDir = {json.dumps(str(static_dir / "js"))};
        const els = {{}};
        const mkEl = (id) => els[id] = els[id] || {{
          id, value: '', checked: true, innerText: '', innerHTML: '', hidden: false,
          style: {{}}, dataset: {{}}, classList: {{ toggle(){{}}, add(){{}}, remove(){{}}, contains:()=>false }},
          setAttribute(){{}}, removeAttribute(){{}}, scrollIntoView(){{}}, focus(){{}},
          querySelectorAll: () => [], querySelector: () => null, closest: () => null
        }};
        const ctx = vm.createContext({{
          window: null, console, Math, Number, String, Array, Object, Set, Date, JSON, RegExp,
          encodeURIComponent, decodeURIComponent,
          localStorage: {{ getItem: () => null, setItem(){{}} }},
          fetch: () => Promise.resolve({{ ok: true, json: () => Promise.resolve({{}}) }}),
          setTimeout: () => 0, clearTimeout: () => {{}}, setInterval: () => 0,
          document: {{
            documentElement: {{ dataset: {{}} }}, body: {{ classList: {{ toggle(){{}} }} }}, title: '',
            getElementById: mkEl, querySelectorAll: () => [], querySelector: () => null, addEventListener: () => {{}}
          }}
        }});
        ctx.window = ctx;
        for (const f of ['api.js', 'cases.js', 'scanner.js', 'dorks.js', 'daily.js', 'hunt.js', 'settings.js', 'infra.js', 'shell.js', 'app.js']) {{
          vm.runInContext(fs.readFileSync(path.join(jsDir, f), 'utf8'), ctx, {{ filename: f }});
        }}
        vm.runInContext(`
          currentHunt = {{
            target: 'gi-de.com',
            brand: {{ domain: 'gi-de.com', title: 'G+D', allowlist: ['gi-de.com'], tokens: ['gi-de'], brand_titles: ['G+D'], icons: [], analytics_ids: [] }},
            stats: {{ registered: 1, high_risk: 1, suspicious: 0, live: 1, ct_hosts: 0, elapsed_sec: 1.2, by_verdict: {{ phishing: 1 }} }},
            candidates: [{{
              domain: 'gi-de-login.xyz', registered_domain: 'gi-de-login.xyz', matching_subdomain: '', original_domain: 'gi-de.com',
              matched_keyword: 'gi-de', matching_technique: 'Exact Brand Match', similarity_percent: 85,
              score: 85, verdict: 'phishing', classification: 'Confirmed Impersonation', fuzzer: 'feed-listed',
              sources: ['phishingdb'], intel: [{{ source: 'phishingdb', match: 'feed', title: 'Phish', time: '2026-11-26' }}],
              dns: {{ a: ['1.2.3.4'], aaaa: [], mx: [], ns: [] }}, dns_status: 'resolves',
              reasons: ['listed in Phishing.Database'], score_breakdown: [{{ points: 45, reason: 'listed in Phishing.Database' }}],
              evidence: null, rdap: null, ct: null
            }}],
            intel: {{ status: [] }}, queries: {{}}, dorks: {{}}, pivots: {{ assets: [] }}, errors: []
          }};
          document.getElementById('hunt-min-score').value = '0';
          document.getElementById('hunt-source-filter').value = 'all';
          document.getElementById('hunt-technique-filter').value = 'all';
          document.getElementById('hunt-sort').value = 'score';
          document.getElementById('hunt-page-size').value = '50';
          huntFilter = 'risky';
          renderHunt(currentHunt);
          if (!document.getElementById('hunt-tbody').innerHTML.includes('gi-de-login.xyz')) {{
            throw new Error('Expected gi-de-login.xyz rendered in hunt-tbody');
          }}
          // Clicking platform card for an offline/unrelated hit while huntFilter='risky' MUST switch to 'all' and show it
          currentHunt.candidates.push({{
            domain: 'gide-offline-phish.top', registered_domain: 'gide-offline-phish.top', matching_subdomain: '', original_domain: 'gi-de.com',
            matched_keyword: 'gi-de', matching_technique: 'Exact Brand Match', similarity_percent: 80,
            score: 45, verdict: 'offline', classification: 'Potential Impersonation', fuzzer: 'intel-hosting',
            sources: ['wayback'], intel: [{{ source: 'wayback', match: 'hosting', title: 'Archived', time: '2026-11-26' }}],
            dns: {{ a: [], aaaa: [], mx: [], ns: [] }}, dns_status: 'nxdomain',
            reasons: ['offline kit'], evidence: null, rdap: null, ct: null
          }});
          huntFilter = 'risky';
          setPlatformFilter('wayback');
          if (huntFilter !== 'all') throw new Error('Expected huntFilter reset to all on platform click');
          if (!document.getElementById('hunt-tbody').innerHTML.includes('gide-offline-phish.top')) {{
            throw new Error('Expected wayback candidate visible when platform card clicked');
          }}

          // Verify Landing Page controller, validation & input preservation
          showLandingPage();
          if (currentTab !== 'home' || document.getElementById('landing-page').hidden !== false) {{
            throw new Error('Expected showLandingPage to activate landing view');
          }}
          document.getElementById('landing-domain-input').value = '';
          handleLandingSubmit({{ preventDefault(){{}} }});
          if (document.getElementById('landing-error').hidden !== false) {{
            throw new Error('Expected empty landing submission to display validation error');
          }}
          document.getElementById('landing-domain-input').value = 'Acme Corp';
          handleLandingSubmit({{ preventDefault(){{}} }});
          if (document.getElementById('landing-domain-input').value !== 'Acme Corp') {{
            throw new Error('Expected invalid input preserved on validation error');
          }}
          if (!document.getElementById('landing-error').innerHTML.includes('openDorksFromLanding')) {{
            throw new Error('Expected Dorks fallback suggestion for bare brand input');
          }}
          toggleLandingMenu(true);
          if (document.getElementById('landing-tools-menu').hidden !== false) {{
            throw new Error('Expected landing tools dropdown to open');
          }}
          switchTab('overview');
          if (document.getElementById('landing-page').hidden !== true) {{
            throw new Error('Expected switchTab to hide landing page');
          }}
        `, ctx);
        """
        proc = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=20)
        assert proc.returncode == 0, proc.stderr or proc.stdout


class TestUrlscanDailyQueries:
    def test_extract_brand_titles_skips_waf_and_collects_metadata(self):
        html = """
        <html>
          <head>
            <title>Just a moment... | Giesecke+Devrient</title>
            <meta property="og:site_name" content="Giesecke+Devrient">
            <meta name="application-name" content="G+D Portal">
            <script type="application/ld+json">
              {"@context":"https://schema.org","@type":"Organization","name":"Giesecke+Devrient GmbH"}
            </script>
          </head>
        </html>
        """
        soup = BeautifulSoup(html, "html.parser")
        titles = dorks.extract_brand_titles("gi-de.com", soup=soup, extra_titles=["gi-de-cloud"])
        assert "gi-de-cloud" in titles
        assert "Giesecke+Devrient" in titles
        assert "G+D Portal" in titles
        assert "Giesecke+Devrient GmbH" in titles
        assert not any("just a moment" in t.lower() for t in titles)

    def test_build_urlscan_daily_queries_excludes_target_domain(self):
        single = dorks.build_urlscan_daily_queries(
            tokens=["gi-de"],
            brand_titles=["Giesecke+Devrient"],
            allowlist=["gi-de.com"],
            hours=24,
            has_key=False,
        )
        assert "NOT page.apexDomain:gi-de.com" in single["domain_query"]

        out = dorks.build_urlscan_daily_queries(
            tokens=["gi-de", "gide", "giesecke"],
            brand_titles=["Giesecke+Devrient"],
            allowlist=["gi-de.com", "giesecke-devrient.com"],
            hours=24,
            has_key=True,
        )
        # Uses 100% free-tier compatible syntax even when a free URLScan API key is present
        assert "page.domain:gi-de*" in out["domain_query"]
        assert "page.domain:giesecke*" in out["domain_query"]
        assert "page.domain:gide*" not in out["domain_query"]
        assert "date:>now-24h" in out["domain_query"]
        assert "NOT page.apexDomain:(gi-de.com OR giesecke-devrient.com)" in out["domain_query"]

        assert 'page.title:"Giesecke+Devrient"' in out["title_query"]
        assert "date:>now-24h" in out["title_query"]
        assert "NOT page.apexDomain:(gi-de.com OR giesecke-devrient.com)" in out["title_query"]

        assert "page.title" in out["combined_query"]
        assert "page.domain" in out["combined_query"]

    def test_ctlogs_fallback_used_when_crtsh_fails(self, monkeypatch):
        def fake_get(url, params=None, headers=None, timeout=None):
            if "crt.sh" in url:
                return _mock_response(502, {})
            return _mock_response(200, {
                "rows": [
                    {"match": "gi-de-login.example", "matches": ["gi-de-login.example"], "not_before": "2026-11-26T00:00:00Z"},
                ]
            })

        monkeypatch.setattr(discovery.requests, "get", fake_get)
        res = discovery.crtsh_search("gi-de", timeout=5, retries=0)
        assert res["error"] is None
        assert "gi-de-login.example" in res["hosts"]

    def test_subdomain_dorks_and_keyword_capture_find_subdomains(self, isolated_env, monkeypatch):
        suite = dorks.generate_impersonation_recon_suite("lntrealty")
        assert "page.domain:lntrealty.*" in suite["master_queries"]["urlscan"]["subdomain_query"]
        assert "lntrealty.%" in [c["query"] for c in suite["crtsh"]]

        pqs = pivots.pivot_queries({"analytics": ["GTM-123456"], "assets": []}, ["example.com"])
        assert any(p["platform"] == "publicwww" and "GTM-123456" in p["query"] for p in pqs)

        def fake_urlscan(query, size=100):
            if "page.domain:lntrealty.*" in query:
                return [{"source": "urlscan", "host": "lntrealty.badhost.tech", "url": "https://lntrealty.badhost.tech", "title": "L&T Login", "extra": {}}]
            return []

        monkeypatch.setitem(impersonation.SEARCHERS, "urlscan", fake_urlscan)
        cap = impersonation.capture_domains_from_keywords("lntrealty", use_ct=False, use_feeds=False, use_dns=False)
        doms = {d["domain"]: d for d in cap["domains"]}
        assert "lntrealty.badhost.tech" in doms
        assert doms["lntrealty.badhost.tech"]["apex_domain"] == "badhost.tech"


class TestWhoisXmlSource:
    def test_whoisxml_registered_in_sources_and_censys_index_preserved(self):
        assert "whoisxml" in config.SOURCES
        assert list(config.SOURCES)[3] == "censys"

    def test_whoisxml_search_merges_and_handles_single_product_403(self, isolated_env, monkeypatch):
        config.save_keys({"WHOISXML_API_KEY": "at_secret_test_key_1234"})

        def fake_post(url, json=None, params=None, headers=None, timeout=None):
            if "brand-alert" in url:
                return _mock_response(200, {
                    "domainsList": [
                        {"domainName": "gi-de-login.com", "action": "added", "date": "2026-11-26"},
                        {"domainName": "gi-de-support.net", "action": "updated", "date": "2026-11-26"},
                    ]
                })
            # Single-product subscription where Discovery returns 403 -> still returns Brand Alert hits!
            return _mock_response(403, {"ErrorMessage": {"msg": "Access denied for discovery subscription"}})

        monkeypatch.setattr(sources.requests, "post", fake_post)
        spec = dorks.build_whoisxml_daily_spec(["gi-de"], ["gi-de.com"], mode="both")
        hits = sources.whoisxml_search(spec, size=50)
        hosts = [h["host"] for h in hits]
        assert hosts == ["gi-de-login.com", "gi-de-support.net"]
        assert hits[0]["source"] == "whoisxml"
        assert hits[0]["extra"]["action"] == "added"

    def test_whoisxml_rotates_on_auth_failure(self, isolated_env, monkeypatch):
        config.save_keys({"WHOISXML_API_KEY": "at_bad_key_1,at_good_key_2"})
        seen_keys = []

        def fake_post(url, json=None, params=None, headers=None, timeout=None):
            seen_keys.append((json or {}).get("apiKey"))
            if (json or {}).get("apiKey") == "at_bad_key_1":
                return _mock_response(401, {"ErrorMessage": {"msg": "Invalid apiKey"}})
            if "domains-subdomains-discovery" in url:
                return _mock_response(200, {"domainsList": ["gi-de-portal.org"]})
            return _mock_response(200, {"domainsList": [{"domainName": "gi-de-sso.com", "action": "added"}]})

        monkeypatch.setattr(sources.requests, "post", fake_post)
        spec = dorks.build_whoisxml_daily_spec(["gi-de"], ["gi-de.com"], mode="both")
        hits = sources.whoisxml_search(spec, size=50)
        assert [h["host"] for h in hits] == ["gi-de-sso.com", "gi-de-portal.org"]
        assert seen_keys[0] == "at_bad_key_1"
        assert "at_good_key_2" in seen_keys

    def test_whoisxml_check_key_never_leaks_secret_and_parses_credits(self, isolated_env, monkeypatch):
        secret = "at_very_secret_token_999"

        monkeypatch.setattr(
            sources.requests,
            "get",
            lambda *a, **kw: _mock_response(200, {"data": [{"product": {"name": "Brand Alert"}, "credits": 250}]}),
        )
        ok = sources.check_key("whoisxml", {"WHOISXML_API_KEY": secret})
        assert ok["ok"] is True
        assert "250" in ok["message"]
        assert secret not in ok["message"]

        monkeypatch.setattr(
            sources.requests,
            "get",
            lambda *a, **kw: _mock_response(200, {"ErrorMessage": {"msg": f"Invalid apiKey {secret} authentication failed"}}),
        )
        bad = sources.check_key("whoisxml", {"WHOISXML_API_KEY": secret})
        assert bad["ok"] is False
        assert bad["kind"] == "auth"
        assert secret not in bad["message"]


class TestDailyIntelEngine:
    def test_free_daily_intel_combines_urlscan_ct_nrd_feeds_dns_and_excludes_own_domain(self, isolated_env, monkeypatch):
        # Zero API keys configured -> 100% Free Mode runs all free engines without errors
        soup = BeautifulSoup("<html><head><title>Giesecke+Devrient Official</title></head></html>", "html.parser")

        class FakeCrawler:
            def __init__(self, **kw):
                self.last_soup = soup

            def normalize_target(self, target):
                return ("gi-de.com", "https://gi-de.com")

            def scan(self, target):
                return {"domain": "gi-de.com", "resolved_url": "https://www.gi-de.com", "reachable": True, "icons": []}

        def fake_urlscan(query, size=100):
            if "page.title:" in query:
                return [
                    {"source": "urlscan", "host": "portal.gi-de.com", "url": "https://portal.gi-de.com", "title": "G+D Portal", "extra": {}},
                    {"source": "urlscan", "host": "gi-de-login.com", "url": "https://gi-de-login.com/auth", "title": "Giesecke+Devrient Login", "time": "2026-11-26T01:00:00Z", "extra": {"result": "https://urlscan.io/result/1/"}},
                    {"source": "urlscan", "host": "evil-gd-clone.com", "url": "https://evil-gd-clone.com", "title": "Giesecke+Devrient Pay", "time": "2026-11-26T02:00:00Z", "extra": {}},
                ]
            return [
                {"source": "urlscan", "host": "gi-de.com", "url": "https://gi-de.com", "title": "Official", "extra": {}},
                {"source": "urlscan", "host": "gi-de-careers.org", "url": "https://gi-de-careers.org", "title": "Careers", "time": "2026-11-26T03:00:00Z", "extra": {}},
            ]

        def fake_ct(token, timeout=15, retries=1, max_hosts=200):
            return {
                "hosts": {
                    "gi-de.com": {"first_seen": "2026-11-26", "last_seen": "2026-11-26", "issuer": "DigiCert", "certs": 1},
                    "gi-de-login.com": {"first_seen": "2026-11-26", "last_seen": "2026-11-26", "issuer": "Let's Encrypt", "certs": 1},
                },
                "error": None,
            }

        def fake_feeds_match(tokens, allowlist, force_refresh=False):
            return {
                "hits": [
                    {"host": "gi-de-verify.shop", "url": None, "feed": "nrd_free", "feed_name": "Free Daily NRD", "via": "host"},
                    {"host": "gi-de-login.com", "url": "https://gi-de-login.com/x", "feed": "openphish", "feed_name": "OpenPhish", "via": "host"},
                ],
                "status": [
                    {"feed": "nrd_free", "name": "Free Daily NRD", "count": 1, "error": None},
                    {"feed": "openphish", "name": "OpenPhish", "count": 1, "error": None},
                ],
                "errors": [],
            }

        def fake_resolve(names, concurrency=80, timeout=2.0):
            return {
                "gi-de.net": {"domain": "gi-de.net", "a": ["203.0.113.55"], "aaaa": [], "mx": [], "ns": [], "status": "resolves", "registered": True},
            }

        monkeypatch.setattr(daily_intel, "FaviconCrawler", FakeCrawler)
        monkeypatch.setitem(daily_intel.SEARCHERS, "urlscan", fake_urlscan)
        monkeypatch.setattr(daily_intel, "crtsh_search", fake_ct)
        monkeypatch.setattr(daily_intel.feeds, "match", fake_feeds_match)
        monkeypatch.setattr(daily_intel, "resolve_domains", fake_resolve)

        report = daily_intel.run_daily_intel("gi-de.com")
        assert report["free_mode"] is True
        assert not any(p.get("error") == "no API key configured" for p in report["platforms"])

        by_domain = {r["domain"]: r for r in report["results"]}
        assert "gi-de.com" not in by_domain
        assert "portal.gi-de.com" not in by_domain

        # Overlap hit detected by URLScan + OpenPhish + crt.sh is prioritized first
        assert report["results"][0]["domain"] == "gi-de-login.com"
        assert set(by_domain["gi-de-login.com"]["platforms"]) == {"urlscan", "openphish", "crt.sh"}
        assert "URLScan.io" in by_domain["gi-de-login.com"]["description"]
        assert "OpenPhish" in by_domain["gi-de-login.com"]["description"]

        assert "gi-de-verify.shop" in by_domain
        assert "nrd_free" in by_domain["gi-de-verify.shop"]["platforms"]
        assert "gi-de.net" in by_domain
        assert "permutation" in by_domain["gi-de.net"]["platforms"]
        assert report["stats"]["total_domains"] == 5

        with TestClient(app_module.app) as client:
            res = client.post("/api/daily-intel", json={"target": "gi-de.com"})
            assert res.status_code == 200
            data = res.json()
            assert data["free_mode"] is True
            assert data["stats"]["total_domains"] == 5
            assert client.post("/api/daily-intel", json={"target": "   "}).status_code == 400


class TestDailyVerifierScoring:
    def test_daily_title_and_whoisxml_signals_boost_risk_score(self):
        cand = {
            "domain": "gi-de-login.com",
            "sources": ["urlscan", "whoisxml"],
            "intel": [
                {"source": "urlscan", "match": "daily_title"},
                {"source": "whoisxml", "match": "whoisxml_brand"},
            ],
            "dns": {"registered": True, "a": ["203.0.113.10"], "mx": [], "ns": []},
            "rdap": {"age_days": 2},
            "evidence": {
                "http": {"status": 200, "final_url": "https://gi-de-login.com"},
                "title": "Giesecke+Devrient Secure Portal",
                "brand_in_title": True,
                "password_form": True,
                "brand_resources": [],
                "shared_analytics": [],
                "visual_distance": None,
                "favicon": {},
                "parked": False,
            },
        }
        brand = {
            "domain": "gi-de.com",
            "tokens": ["gi-de", "gide"],
            "allowlist": ["gi-de.com"],
            "title": "Giesecke+Devrient",
            "brand_titles": ["Giesecke+Devrient"],
        }
        score, verdict, reasons = verifier.score_candidate(cand, brand)
        assert score >= 70
        assert verdict == "phishing"
        joined = " ".join(reasons).lower()
        assert "urlscan" in joined
        assert "whoisxml" in joined
