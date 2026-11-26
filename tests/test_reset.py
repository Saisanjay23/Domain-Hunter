"""Reset all data: verified backup first, only this application's collections, guards, audit, restore."""
import os
import uuid
from unittest import mock

import pytest

from core import config, investigations, reset
from core import scheduler_store as ss
from core.store import get_store


LIVE_URI = os.environ.get("BRAND_HUNTER_TEST_MONGO_URI")


@pytest.fixture
def populated(isolated_store, tmp_path, monkeypatch):
    """mongomock by default; a throwaway bih_test_* database on a real server when BRAND_HUNTER_TEST_MONGO_URI is set."""
    monkeypatch.setattr(config, "PROJECT_ROOT", str(tmp_path))                 # backups go to the test folder
    s = isolated_store
    if LIVE_URI:
        from pymongo import MongoClient
        from core import store as store_mod
        from core.mongostore import MongoStore
        s = MongoStore(MongoClient(LIVE_URI, serverSelectionTimeoutMS=4000), f"bih_test_{uuid.uuid4().hex[:8]}")
        store_mod.set_store(s)
        request_cleanup = s
    else:
        request_cleanup = None
    db = s.db
    ss.ensure_indexes(db)
    s.save_hunt("h1", {"target": "paypal.com", "depth": "quick", "stats": {}, "candidates": [{"domain": "a.com", "score": 80, "verdict": "phishing"}]})
    s.triage_set("paypal.com", "a.com", "confirmed", "note")
    s.watch_add("paypal.com", "quick", 24, 45, "", [])
    s.alert_add("paypal.com", "info", "t", "b", None)
    b = ss.create_batch(db, {"name": "Banks", "schedule": {"frequency": "manual"}})
    ss.batch_add_entries(db, b["_id"], [{"domain": "paypal.com", "keywords": ["paypal"]}])
    investigations.save(db, "0123456789ab", {}, {"seed": "x.example.com", "domains": [], "nodes": [], "edges": [], "actor": {}, "stats": {}})
    ss.audit(db, "127.0.0.1", "batch.create", "batch", b["_id"])
    db.other_tool_data.insert_one({"_id": 1, "keep": True})                    # not ours: must survive
    yield db, tmp_path
    if request_cleanup is not None:
        request_cleanup._client.drop_database(request_cleanup.db_name)
        request_cleanup.close()


def test_preview_lists_only_application_collections(populated):
    db, _ = populated
    p = reset.preview(db)
    assert "other_tool_data" not in p["collections"] and "audit_logs" not in p["collections"]
    assert p["collections"]["hunts"] == 1 and p["collections"]["infra_investigations"] == 1 and p["total"] > 5
    assert "audit_logs" in reset.preview(db, include_audit=True)["collections"]


def test_reset_backs_up_wipes_audits_and_restores(populated):
    db, tmp = populated
    before = {c: db[c].count_documents({}) for c in ("hunts", "candidates", "triage", "watchlist", "alerts", "monitored_domains",
                                                        "scan_batches", "infra_investigations")}
    out = reset.reset_all(db, actor="127.0.0.1")
    assert out["transaction"] is ss.supports_transactions(db)                  # one transaction on a replica set
    assert os.path.isdir(out["backup"]["folder"]) and out["backup"]["folder"].startswith(str(tmp))
    assert out["backup"]["collections"]["hunts"] == 1 and out["backup"]["collections"]["audit_logs"] == 1   # audit is backed up too
    for c in before:
        assert db[c].count_documents({}) == 0, c
    assert db.other_tool_data.count_documents({}) == 1
    actions = [a["action"] for a in ss.audit_list(db)]
    assert actions[0] == "data.reset_all" and "batch.create" in actions          # audit history kept, reset recorded
    assert get_store().list_hunts() == [] and get_store().watch_list() == []

    restored = reset.restore_backup(db, out["backup"]["folder"])
    assert restored["hunts"] == 1 and {c: db[c].count_documents({}) for c in before} == before
    assert reset.restore_backup(db, out["backup"]["folder"])["hunts"] == 0     # idempotent


def test_reset_refuses_while_a_batch_runs(populated):
    db, _ = populated
    ss.create_execution(db, ss.get_batch(db, db.scan_batches.find_one()["_id"]), "manual")
    with pytest.raises(reset.ResetError):
        reset.reset_all(db)
    assert db.hunts.count_documents({}) == 1


def test_backup_failure_deletes_nothing(populated):
    db, _ = populated
    with mock.patch.object(reset, "backup", side_effect=reset.ResetError("disk full")):
        with pytest.raises(reset.ResetError):
            reset.reset_all(db)
    assert db.hunts.count_documents({}) == 1


def test_reset_api_guards(populated):
    from fastapi.testclient import TestClient
    import app as app_module
    db, _ = populated
    c = TestClient(app_module.app)
    with mock.patch.multiple(app_module, SETTINGS_ALLOWED_CLIENTS={"testclient"}, SETTINGS_ALLOWED_HOSTS={"testserver"}):
        assert c.get("/api/data/reset").json()["confirm_text"] == "DELETE ALL DATA"
        assert c.post("/api/data/reset", json={"confirm": "delete all data"}).status_code == 400     # exact phrase only
        assert c.post("/api/data/reset", json={"confirm": "DELETE ALL DATA"}, headers={"Origin": "https://evil.example"}).status_code == 403
        r = c.post("/api/data/reset", json={"confirm": "DELETE ALL DATA", "clear_source_log": False})
        assert r.status_code == 200 and r.json()["total"] > 5
        assert db.hunts.count_documents({}) == 0
    assert c.post("/api/data/reset", json={"confirm": "DELETE ALL DATA"}).status_code == 403          # remote clients never
