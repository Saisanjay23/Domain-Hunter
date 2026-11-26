"""
Browser tests (Playwright + Chromium) of the Scan Scheduler, Data Management, Infrastructure history and Storage pages.

The real app is served by uvicorn on a free local port inside this process, backed by the per-test in-memory
MongoDB (conftest.isolated_store). Scans use a deterministic fake engine; everything else (HTML, CSS, JavaScript,
API, database layer) is the production code. Skipped automatically when Playwright or its browser is missing.

    python -m pytest tests/test_ui.py -q            # headless
    PWDEBUG=1 python -m pytest tests/test_ui.py     # watch it
"""
import re
import socket
import threading
import time

import pytest

pw = pytest.importorskip("playwright.sync_api")

from core import config, investigations                                # noqa: E402
from core import scheduler_store as ss                                   # noqa: E402
from test_scheduler import FakeHunts, cand                               # noqa: E402

pytestmark = pytest.mark.ui


@pytest.fixture(scope="module")
def server():
    import uvicorn
    import app as app_module
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    srv = uvicorn.Server(uvicorn.Config(app_module.app, host="127.0.0.1", port=port, log_level="warning", lifespan="off"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    srv.should_exit = True
    t.join(5)


@pytest.fixture(scope="module")
def browser():
    with pw.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as e:  # browser binaries not installed
            pytest.skip(f"Chromium for Playwright is not available: {e}")
        yield b
        b.close()


@pytest.fixture
def page(browser, server, isolated_store, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "PROJECT_ROOT", str(tmp_path))          # reset backups go to the test folder
    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    pg = ctx.new_page()
    errors = []
    pg.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
    pg.on("console", lambda m: errors.append(f"console: {m.text}") if m.type == "error" and "status of 4" not in m.text else None)
    pg.on("dialog", lambda d: d.accept("false positive: partner site") if d.type == "prompt" else d.accept())
    pg.goto(server)
    pg.wait_for_function("typeof switchTab === 'function'")
    pg.errors = errors
    yield pg
    ctx.close()
    assert errors == [], errors                                          # no JavaScript errors on any page


@pytest.fixture
def engine(monkeypatch):
    from api.routes import scheduler as routes
    hunts = FakeHunts()
    routes.ENGINE.runner, routes.ENGINE.resolver = hunts, (lambda hosts: {})
    routes.ENGINE.poll_seconds, routes.ENGINE.stagger_seconds = 0.01, 0
    yield routes.ENGINE, hunts
    routes.ENGINE.runner = routes.ENGINE.resolver = None
    routes.ENGINE.poll_seconds, routes.ENGINE.stagger_seconds = 2.0, 2.0


def go(page, tab):
    page.evaluate(f"switchTab('{tab}')")


def test_scheduler_create_run_review_dismiss_and_export(page, engine, isolated_store):
    eng, hunts = engine
    hunts.script = {"paypal.com": [cand("paypal-verify.com", 90, "Confirmed Impersonation", "phishing"), cand("paypal-x.com", 55)],
                    "amazon.com": [cand("amaz0n-help.com", 60)]}
    go(page, "scheduler")
    page.get_by_role("button", name="+ New batch").first.click()
    page.fill("#sch-editor [name=name]", "UI test brands")
    page.fill("#sch-imp-text", "https://www.paypal.com/signin, paypal; venmo\nnot a domain\nPAYPAL.com, braintree")
    page.get_by_role("button", name="Validate list").click()
    page.wait_for_selector("#sch-imp-out tbody tr")
    assert page.locator(".sch-import-summary").inner_text().count("valid") >= 1
    page.fill("[data-imp-fix]", "amazon.com, amazon")                   # correct the invalid line
    page.get_by_role("button", name="Re-check corrections").click()
    page.wait_for_function("document.querySelector('.sch-import-summary')?.innerText.includes('2 valid')")
    assert page.locator("#sch-imp-out").inner_text().count("Invalid") == 0
    page.click('#sch-dialog [data-sch="freq"][data-v="manual"]')
    page.get_by_role("button", name="Create batch").click()
    page.wait_for_selector("#sch-root tbody tr[data-sch-row]")
    assert page.locator("#sch-root tbody tr[data-sch-row]").count() == 2

    page.get_by_role("button", name="Run now").click()
    page.wait_for_selector("text=Live run")
    eng.tick(run_inline=True)                                            # the server-side engine does the work
    page.evaluate("schRefresh()")
    page.wait_for_selector("#sch-root .st-completed")
    assert "Completed" in page.locator("#sch-root").inner_text()

    page.locator("#sch-root tr[data-sch-row]", has_text="paypal.com").click()
    page.wait_for_selector("text=New Discoveries")
    assert page.locator("#sch-root tbody tr").count() == 2
    page.click('[data-sch="domain-tab"][data-tab="confirmed"]')
    page.wait_for_function("document.querySelectorAll('#sch-root tbody tr').length === 1")
    page.click('[data-sch="domain-tab"][data-tab="potential"]')
    page.wait_for_selector("text=paypal-x.com")
    page.check("[data-sch-check]")
    assert "1 selected" in page.locator("#sch-bulk").inner_text()
    page.get_by_role("button", name="Dismiss as false positive").click()
    page.wait_for_function("!document.querySelector('[data-sch-check]')")
    page.click('[data-sch="domain-tab"][data-tab="dismissed"]')
    page.wait_for_selector("text=paypal-x.com")

    href = page.get_attribute("a:has-text('Export CSV')", "href")
    csv_text = page.request.get(page.url.rstrip("/") + href).text()
    assert csv_text.startswith("host,") and "paypal-verify.com" in csv_text and "paypal-x.com" not in csv_text   # dismissed excluded
    did = ss.get_domain(isolated_store.db, isolated_store.db.monitored_domains.find_one({"domain": "paypal.com"})["_id"])["_id"]
    assert isolated_store.db.impersonation_findings.find_one({"_id": f"{did}:paypal-x.com"})["dismissed_reason"] == "false positive: partner site"


def test_data_management_typed_delete_and_full_reset(page, engine, isolated_store):
    eng, hunts = engine
    db = isolated_store.db
    hunts.script = {"paypal.com": [cand("p-1.com")], "netflix.com": [cand("n-1.com")]}
    b = ss.create_batch(db, {"name": "Data", "schedule": {"frequency": "manual"}})
    ss.batch_add_entries(db, b["_id"], [{"domain": "paypal.com"}, {"domain": "netflix.com"}])
    ss.create_execution(db, ss.get_batch(db, b["_id"]), "manual")
    eng.tick(run_inline=True)
    isolated_store.save_hunt("manual-1", {"target": "paypal.com", "depth": "quick", "stats": {}, "candidates": []})

    go(page, "data")
    page.wait_for_selector("#dm-root tbody tr")
    page.locator("#dm-root tr", has_text="netflix.com").locator('[data-dm="domain"]').click()
    page.wait_for_selector("#dm-confirm-input")
    page.fill("#dm-confirm-input", "netflix")
    assert page.is_disabled("#dm-go")
    page.fill("#dm-confirm-input", "netflix.com")
    assert page.is_enabled("#dm-go")
    page.click("#dm-go")
    page.wait_for_function("!document.querySelector('#dm-dialog').open")
    page.wait_for_function("![...document.querySelectorAll('#dm-root tbody tr')].some(r => r.innerText.includes('netflix.com'))")
    assert "domain.delete" in page.locator(".dm-audit").inner_text()           # and the audit log shows it
    assert db.monitored_domains.count_documents({}) == 1 and db.impersonation_findings.count_documents({"original_domain": "paypal.com"}) == 1

    page.get_by_role("button", name="Reset all data…").click()
    page.wait_for_selector("#dm-confirm-input")
    page.fill("#dm-confirm-input", "delete all data")                    # exact phrase only
    assert page.is_disabled("#dm-go")
    page.fill("#dm-confirm-input", "DELETE ALL DATA")
    with page.expect_navigation(timeout=15000):                          # the app reloads itself after a reset
        page.click("#dm-go")
    for coll in ("hunts", "monitored_domains", "impersonation_findings", "scan_batches", "scan_jobs"):
        assert db[coll].count_documents({}) == 0, coll
    assert db.audit_logs.find_one({"action": "data.reset_all"})


def test_infrastructure_history_open_and_delete(page, isolated_store):
    db = isolated_store.db
    investigations.ensure_indexes(db)
    result = {"seed": "login.paypal.secure-check.example", "seed_root": "secure-check.example", "depth": 2, "keywords": ["paypal"],
              "nodes": [{"id": "domain:login.paypal.secure-check.example", "type": "domain", "label": "login.paypal.secure-check.example",
                         "data": {"confidence": "seed"}}], "edges": [],
              "domains": [{"domain": "login.paypal.secure-check.example", "root": "secure-check.example", "depth": 0, "discovered_via": "seed",
                           "link_confidence": "seed", "link_path": [], "dns": {"a": [], "aaaa": [], "mx": [], "ns": []}, "dns_status": "resolves",
                           "artifacts": {}, "signals": {}, "intent": [], "title": "PayPal Login"}],
              "actor": {"mode": "malicious", "confidence": "single domain", "sophistication": 35, "summary": "UI test dossier", "intent": [],
                        "targets": [], "clones": [], "predictions": {"next_domains": []}},
              "stats": {"domains_profiled": 1, "nodes": 1, "edges": 0, "linked_high": 0, "linked_medium": 0, "linked_low": 0, "elapsed_sec": 1},
              "sources": [], "errors": [], "generated_at": "2026-11-26T00:00:00+00:00", "disclaimer": "test"}
    investigations.save(db, "a1b2c3d4e5f6", {"depth": 2}, result)
    go(page, "infra")
    page.wait_for_selector(".infra-hrow")
    assert "login.paypal.secure-check.example" in page.locator("#infra-history").inner_text()
    page.locator(".infra-hrow").get_by_role("button", name="Open").click()
    page.wait_for_selector("#infra-results-section:not([hidden])")
    assert "Saved investigation from" in page.locator("#infra-changes").inner_text()
    page.locator(".infra-hrow").get_by_role("button", name="Delete").click()
    page.wait_for_function("!document.querySelector('.infra-hrow')")
    assert db.infra_investigations.count_documents({}) == 0


def test_storage_page_is_mongodb_only(page):
    go(page, "storage")
    page.wait_for_selector("#storage-active .badge")
    text = page.locator("#storage-page").inner_text()
    assert "MongoDB" in text and "Transactions" in text
    assert not re.search("sqlite", page.content(), re.I)


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_scheduler_fits_a_phone_in_both_themes(page, theme, isolated_store):
    ss.create_batch(isolated_store.db, {"name": "A very long batch name for the phone layout check", "schedule": {"frequency": "daily", "time": "02:00", "timezone": "Asia/Kolkata"}})
    page.emulate_media(color_scheme=theme)
    page.set_viewport_size({"width": 390, "height": 844})
    go(page, "scheduler")
    page.wait_for_selector(".sch-card")
    overflow = page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
    assert overflow <= 0, f"horizontal overflow of {overflow}px"
