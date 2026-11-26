"""
MongoDB storage: one contract suite run against MongoDB (mongomock) and, optionally, a real server;
plus connection settings, connection switching, legacy SQLite import, redaction and the storage API.

Run the live variant against a real MongoDB with:
    BRAND_HUNTER_TEST_MONGO_URI=mongodb://127.0.0.1:27017 python -m pytest tests/test_mongo.py
A throwaway database (bih_test_<random>) is created and dropped.
"""
import json
import os
import sqlite3
import tempfile
import time
import unittest
import uuid
import zlib
from unittest import mock

import mongomock

from core import config, migrate, mongostore, store as store_mod
from core.mongostore import MongoStore, describe_uri, redact
from core.store import DEFAULT_MONGODB_URI, StoreError, StoreUnavailable, get_store
from test_settings import EnvSandbox

try:
    from fastapi.testclient import TestClient
    import app as app_module
    HAVE_CLIENT = True
except Exception:
    HAVE_CLIENT = False

LIVE_URI = os.environ.get("BRAND_HUNTER_TEST_MONGO_URI")


def cand(domain, score=80, verdict="phishing", **kw):
    return {"domain": domain, "score": score, "verdict": verdict, "sources": ["urlscan"], "reasons": ["why"], **kw}


def result(target="paypal.com", cands=None, **extra):
    return {"target": target, "depth": "quick", "stats": {"registered": len(cands or []), **extra.pop("stats", {})},
            "candidates": cands or [], **extra}

LEGACY_SCHEMA = """
CREATE TABLE hunts (id TEXT PRIMARY KEY, target TEXT NOT NULL, created REAL NOT NULL, depth TEXT, high_risk INTEGER DEFAULT 0,
    suspicious INTEGER DEFAULT 0, registered INTEGER DEFAULT 0, new_count INTEGER DEFAULT 0, scheduled INTEGER DEFAULT 0, result BLOB NOT NULL);
CREATE TABLE hunt_candidates (hunt_id TEXT NOT NULL, domain TEXT NOT NULL, score INTEGER, verdict TEXT, PRIMARY KEY (hunt_id, domain));
CREATE TABLE triage (brand TEXT NOT NULL, domain TEXT NOT NULL, status TEXT NOT NULL, note TEXT DEFAULT '', updated REAL NOT NULL, PRIMARY KEY (brand, domain));
CREATE TABLE watchlist (id INTEGER PRIMARY KEY AUTOINCREMENT, brand TEXT UNIQUE NOT NULL, depth TEXT DEFAULT 'standard',
    interval_hours INTEGER DEFAULT 24, min_score INTEGER DEFAULT 45, webhook_url TEXT DEFAULT '', enabled INTEGER DEFAULT 1,
    allowlist TEXT DEFAULT '', last_run REAL, last_hunt TEXT, last_status TEXT, created REAL NOT NULL);
CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, created REAL NOT NULL, brand TEXT, level TEXT, title TEXT,
    body TEXT, hunt_id TEXT, read INTEGER DEFAULT 0, delivery TEXT DEFAULT '');
"""


def write_legacy_db(path):
    """A SQLite file exactly as the retired SQLite backend wrote it."""
    db = sqlite3.connect(path)
    db.executescript(LEGACY_SCHEMA)
    for hid, res, created, sched in (("h1", result(cands=[cand("a.com", 90), cand("b.com", 20, "no_website")], stats={"high_risk": 1}), time.time() - 500, 0),
                                     ("h2", result(cands=[cand("a.com", 90)]), time.time(), 1)):
        res = dict(res, hunt_id=hid, created=created)
        db.execute("INSERT INTO hunts(id,target,created,depth,scheduled,result) VALUES(?,?,?,?,?,?)",
                   (hid, res["target"], created, "quick", sched, zlib.compress(json.dumps(res).encode(), 6)))
        db.executemany("INSERT INTO hunt_candidates VALUES(?,?,?,?)", [(hid, c["domain"], c["score"], c["verdict"]) for c in res["candidates"]])
    db.execute("INSERT INTO triage VALUES('paypal.com','a.com','confirmed','seen live',1700000000.0)")
    db.execute("INSERT INTO watchlist(brand,depth,interval_hours,min_score,webhook_url,enabled,allowlist,last_run,last_hunt,last_status,created) "
               "VALUES('paypal.com','quick',6,45,'https://hooks.example/SECRET',0,'paypal.me',1700000100.0,'h2','ok',1700000000.0)")
    db.execute("INSERT INTO alerts(created,brand,level,title,body,hunt_id,read,delivery) "
               "VALUES(1700000200.0,'paypal.com','high','alert one','body','h2',1,'webhook: delivered')")
    db.commit()
    db.close()


# ============================================================== the contract every backend must satisfy
class StoreContract:
    def make_store(self):  # pragma: no cover - overridden
        raise NotImplementedError

    def setUp(self):
        self.s = self.make_store()

    def test_history_diff_first_seen_and_ordering(self):
        r1 = result(cands=[cand("b.com", 10, "no_website"), cand("a.com", 90)])
        self.s.decorate(r1, exclude_id="h1")
        self.assertFalse(r1["stats"]["has_previous"])
        self.s.save_hunt("h1", r1, created=time.time() - 1000)

        r2 = result(cands=[cand("a.com", 90), cand("c.com", 75)])
        self.s.decorate(r2, exclude_id="h2")
        self.assertEqual([(c["domain"], c["is_new"]) for c in r2["candidates"]], [("a.com", False), ("c.com", True)])
        self.assertEqual((r2["stats"]["new_domains"], r2["stats"]["new_risky"]), (1, 1))
        self.assertLess(r2["candidates"][0]["first_seen"], time.time() - 900)
        self.s.save_hunt("h2", r2, scheduled=True)

        hunts = self.s.list_hunts()
        self.assertEqual([h["id"] for h in hunts], ["h2", "h1"])
        self.assertEqual((hunts[0]["new_count"], bool(hunts[0]["scheduled"]), bool(hunts[1]["scheduled"])), (1, True, False))
        self.assertEqual([h["id"] for h in self.s.list_hunts(target="netflix.com")], [])
        got = self.s.get_hunt("h1")
        self.assertEqual([c["domain"] for c in got["candidates"]], ["a.com", "b.com"])   # highest score first
        self.assertTrue(self.s.delete_hunt("h1"))
        self.assertIsNone(self.s.get_hunt("h1"))
        self.assertFalse(self.s.delete_hunt("h1"))
        self.assertEqual(self.s.stats()["hunts"], 1)

    def test_other_brands_do_not_mix_and_previous_is_the_latest(self):
        self.s.save_hunt("h1", result("paypal.com", [cand("a.com")]), created=time.time() - 50)
        self.s.save_hunt("h2", result("paypal.com", [cand("b.com")]), created=time.time() - 10)
        other = result("netflix.com", [cand("a.com")])
        self.s.decorate(other, exclude_id="x")
        self.assertFalse(other["stats"]["has_previous"])
        again = result("paypal.com", [cand("a.com"), cand("b.com")])
        self.s.decorate(again, exclude_id="h3")
        self.assertEqual([c["is_new"] for c in again["candidates"]], [True, False])   # compared with h2 only

    def test_keys_with_dots_and_sets_survive(self):
        r = result(cands=[cand("a.com", ct={"hosts": ["a.com"]}, tags={"x", "y"})], dorks={"fofa": {"domain.wildcard": "x"}})
        self.s.save_hunt("h1", r)
        got = self.s.get_hunt("h1")
        self.assertEqual(sorted(got["candidates"][0]["tags"]), ["x", "y"])
        self.assertIn("domain_wildcard", got["dorks"]["fofa"])

    def test_previews_trimmed_to_top_candidates(self):
        many = [cand(f"d{i}.com", score=i, evidence={"preview": "data:image/png;base64,AAAA"}) for i in range(60)]
        self.s.save_hunt("h1", result(cands=many))
        kept = [c for c in self.s.get_hunt("h1")["candidates"] if (c.get("evidence") or {}).get("preview")]
        self.assertEqual(len(kept), store_mod.PREVIEW_KEEP)

    def test_triage(self):
        self.s.save_hunt("h1", result(cands=[cand("a.com"), cand("b.com")]))
        saved = self.s.triage_set("paypal.com", "a.com", "false_positive", "partner site")
        self.assertEqual(saved["status"], "false_positive")
        r = self.s.get_hunt("h1")
        self.s.decorate(r, compute_new=False)
        self.assertEqual([c["triage"]["status"] for c in r["candidates"]], ["false_positive", "open"])
        self.assertEqual(len(self.s.triage_all()), 1)
        self.s.triage_set("paypal.com", "a.com", "open", "")
        self.assertEqual(self.s.triage_get("paypal.com"), {})
        with self.assertRaises(StoreError):
            self.s.triage_set("paypal.com", "a.com", "bogus")

    def test_watchlist_claim_and_secrets(self):
        url = "https://hooks.example/services/SECRETTOKEN1234"
        wid = self.s.watch_add("paypal.com", "quick", 6, 50, url, ["paypal.me"])
        w = self.s.watch_get(wid)
        self.assertNotIn("SECRETTOKEN", repr(w))
        self.assertEqual((w["allowlist"], w["enabled"], w["webhook"]["set"]), (["paypal.me"], True, True))
        self.assertEqual(self.s.watch_get(wid, include_secret=True)["webhook_url"], url)
        with self.assertRaises(StoreError):
            self.s.watch_add("paypal.com", "quick", 6, 50, "", [])
        with self.assertRaises(StoreError):
            self.s.watch_add("x.com", "quick", 6, 50, "ftp://nope", [])

        now = time.time()
        self.assertTrue(self.s.watch_claim(wid, now - 6 * 3600, now))            # never run: due, claimed
        self.assertFalse(self.s.watch_claim(wid, now - 6 * 3600, now + 1))      # already claimed: a second instance loses
        self.assertEqual(self.s.watch_get(wid)["last_status"], "running")
        self.s.watch_update(wid, last_run=now - 7 * 3600, last_status="ok")
        self.assertTrue(self.s.watch_claim(wid, now - 6 * 3600, now))            # overdue again
        self.s.watch_update(wid, enabled=False)
        self.s.watch_update(wid, last_run=None)
        self.assertFalse(self.s.watch_claim(wid, now, now))                      # disabled watches are never claimed
        self.s.watch_update(wid, enabled=True, webhook_url="")
        w = self.s.watch_get(wid)
        self.assertFalse(w["webhook"]["set"])
        self.assertEqual(len(self.s.watch_list()), 1)
        self.assertTrue(self.s.watch_delete(wid))
        self.assertIsNone(self.s.watch_get(wid))

    def test_alerts(self):
        a = self.s.alert_add("paypal.com", "high", "t1", "b", "h1", "delivered", created=time.time() - 10)
        self.s.alert_add("paypal.com", "info", "t2", "b", None)
        self.assertEqual(self.s.alert_unread(), 2)
        self.assertEqual([x["title"] for x in self.s.alert_list()], ["t2", "t1"])    # newest first
        self.s.alert_mark_read(a)
        self.assertEqual(self.s.alert_unread(), 1)
        self.s.alert_mark_read()
        self.assertEqual(self.s.alert_unread(), 0)
        self.assertEqual(self.s.alert_list()[1]["delivery"], "delivered")


class TestMongoMockContract(StoreContract, unittest.TestCase):
    def make_store(self):
        return MongoStore(mongomock.MongoClient(), f"bih_{uuid.uuid4().hex[:8]}")


@unittest.skipUnless(LIVE_URI, "set BRAND_HUNTER_TEST_MONGO_URI to run against a real MongoDB")
class TestLiveMongoContract(StoreContract, unittest.TestCase):
    def make_store(self):
        from pymongo import MongoClient
        name = f"bih_test_{uuid.uuid4().hex[:8]}"
        client = MongoClient(LIVE_URI, serverSelectionTimeoutMS=4000)
        self.addCleanup(client.close)
        self.addCleanup(client.drop_database, name)
        return MongoStore(client, name)


# ============================================================== URI helpers & credential redaction
class TestUriHelpers(unittest.TestCase):
    def test_describe_and_redact(self):
        d = describe_uri("mongodb+srv://bob:p%40ss@c0.abc.mongodb.net/mydb?retryWrites=true")
        self.assertEqual((d["srv"], d["hosts"], d["database"], d["has_credentials"]), (True, ["c0.abc.mongodb.net"], "mydb", True))
        d = describe_uri("mongodb://h1:27017,h2:27017/?replicaSet=rs0")
        self.assertEqual((d["hosts"], d["database"], d["has_credentials"]), (["h1:27017", "h2:27017"], None, False))
        uri = "mongodb://bob:p%40ss@db.example:27017/x"
        msg = redact(f"auth failed for {uri} (user bob, password p@ss)", uri)
        for secret in ("bob", "p%40ss", "p@ss"):
            self.assertNotIn(secret, msg)
        self.assertEqual(mongostore.resolve_db_name("mongodb://h/x", None), "x")
        self.assertEqual(mongostore.resolve_db_name("mongodb://h/", "chosen"), "chosen")
        self.assertEqual(mongostore.resolve_db_name("mongodb://h/", None), "brand_hunter")

    def test_connection_failures_are_redacted_and_fast(self):
        uri = "mongodb://bob:SuperSecret@127.0.0.1:1/x"
        t = time.time()
        res = mongostore.check_connection(uri, timeout_ms=600)
        self.assertFalse(res["ok"])
        self.assertNotIn("SuperSecret", res["message"])
        self.assertLess(time.time() - t, 6)
        with self.assertRaises(StoreUnavailable) as ctx:
            mongostore.connect_mongo(uri, timeout_ms=600)
        self.assertNotIn("SuperSecret", str(ctx.exception))
        self.assertIn("not reachable", str(ctx.exception))


# ============================================================== settings + backend selection + migration
class TestBackendSelection(EnvSandbox):
    def setUp(self):
        super().setUp()
        self.db_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.db_dir.cleanup)
        env = mock.patch.dict(os.environ, {"BRAND_HUNTER_DB": os.path.join(self.db_dir.name, "local.db")})
        env.start()
        self.addCleanup(env.stop)
        store_mod.set_store(None)                         # unpin the test store: exercise the real selection logic
        self.addCleanup(lambda: store_mod.set_store(None))

    def tearDown(self):
        store_mod.close_all()
        store_mod.set_store(None)
        super().tearDown()

    def test_uri_validation_and_single_value_semantics(self):
        with self.assertRaises(config.SettingsError):
            config.save_keys({"MONGODB_URI": "http://nope"})
        with self.assertRaises(config.SettingsError):
            config.save_keys({"MONGODB_URI": "mongodb://h/db name"})
        with self.assertRaises(config.SettingsError):
            config.save_keys({"MONGODB_DB": "bad name!"})
        uri = "mongodb://u:p@h1:27017,h2:27017,h3:27017/?replicaSet=rs0"
        config.save_keys({"MONGODB_URI": uri, "MONGODB_DB": "hunter"})
        self.assertEqual(config.get_list("MONGODB_URI"), [uri])                  # commas are NOT a key list
        self.assertEqual(config.get("MONGODB_URI"), uri)
        with self.assertRaises(config.SettingsError):
            config.add_key("MONGODB_URI", "mongodb://another")                  # not a rotation list

    def test_switches_with_the_configuration_and_caches_failures(self):
        built = []

        def fake_connect(uri, db=None):
            built.append((uri, db))
            return MongoStore(mongomock.MongoClient(), db or "brand_hunter")

        with mock.patch.object(mongostore, "connect_mongo", side_effect=fake_connect):
            local = get_store()
            self.assertEqual(local.backend, "mongodb")
            self.assertEqual(built[-1], (DEFAULT_MONGODB_URI, None))              # no URI configured: the local default server
            self.assertIs(get_store(), local)                                    # cached
            config.save_keys({"MONGODB_URI": "mongodb://127.0.0.1:27017", "MONGODB_DB": "bih_sel"})
            sel = get_store()
            self.assertIsNot(sel, local)
            self.assertEqual(built[-1], ("mongodb://127.0.0.1:27017", "bih_sel"))
            self.assertIs(get_store(), sel)
            config.save_keys({"MONGODB_URI": "", "MONGODB_DB": ""})
            self.assertEqual(get_store().backend, "mongodb")                     # removing the URI: the default server, never SQLite
            self.assertEqual(built[-1], (DEFAULT_MONGODB_URI, None))

        calls = []

        def down(uri, db=None):
            calls.append(uri)
            raise StoreUnavailable("MongoDB is not reachable: ServerSelectionTimeoutError")

        store_mod._failure = None
        with mock.patch.object(mongostore, "connect_mongo", side_effect=down):
            config.save_keys({"MONGODB_URI": "mongodb://down.example:27017"})
            for _ in range(3):
                with self.assertRaises(StoreUnavailable):
                    get_store()
            self.assertEqual(len(calls), 1)                                      # the failure is cached, not retried per call
            store_mod._failure = (store_mod._failure[0], time.time() - 60, store_mod._failure[2])
            with self.assertRaises(StoreUnavailable):
                get_store()
            self.assertEqual(len(calls), 2)                                      # ...and retried after the back-off

    def test_legacy_sqlite_import_backs_up_validates_and_is_idempotent(self):
        path = os.path.join(self.db_dir.name, "local.db")
        write_legacy_db(path)
        before = open(path, "rb").read()
        dst = MongoStore(mongomock.MongoClient(), "bih_mig")
        backups = os.path.join(self.db_dir.name, "backups")

        rep = migrate.migrate_sqlite(path, dst, backup_dir=backups)
        counts = rep["copied"]
        self.assertEqual((counts["hunts"], counts["triage"], counts["watchlist"], counts["alerts"]), (2, 1, 1, 1))
        self.assertTrue(rep["validation"]["ok"], rep["validation"])
        self.assertEqual(rep["validation"]["candidates"], {"source": 3, "destination": 3})
        self.assertTrue(os.path.isfile(rep["backup"]["path"]))
        self.assertEqual(rep["backup"]["counts"]["hunts"], 2)
        self.assertEqual(open(path, "rb").read(), before)                         # the source is untouched (read-only)
        self.assertFalse(rep["source_deleted"])

        self.assertEqual([h["id"] for h in dst.list_hunts()], ["h2", "h1"])
        self.assertTrue(dst.list_hunts()[0]["scheduled"])
        self.assertEqual(dst.get_hunt("h1")["candidates"][0]["domain"], "a.com")
        self.assertEqual(dst.triage_get("paypal.com")["a.com"], {"status": "confirmed", "note": "seen live", "updated": 1700000000.0})
        w = dst.watch_list(include_secret=True)[0]
        self.assertEqual((w["webhook_url"], w["enabled"], w["last_status"], w["allowlist"]), ("https://hooks.example/SECRET", False, "ok", ["paypal.me"]))
        a = dst.alert_list()[0]
        self.assertEqual((a["title"], a["read"], a["created"]), ("alert one", True, 1700000200.0))

        again = migrate.migrate_sqlite(path, dst, backup_dir=backups)            # repeat: nothing duplicated
        self.assertEqual((again["copied"]["watchlist"], again["copied"]["watchlist_skipped"], again["copied"]["alerts"],
                          again["copied"]["alerts_skipped"]), (0, 1, 0, 1))
        self.assertTrue(again["validation"]["ok"])
        self.assertEqual((len(dst.list_hunts()), len(dst.watch_list()), len(dst.alert_list()), dst.stats()["candidates"]), (2, 1, 1, 3))
        self.assertNotEqual(again["backup"]["path"], rep["backup"]["path"])      # a new backup every run, earlier ones kept
        self.assertEqual(len(os.listdir(backups)), 2)
        hist = migrate.migration_history(dst)
        self.assertEqual((len(hist), hist[0]["runs"]), (1, 2))                    # one record per source checksum

    def test_legacy_import_refuses_a_non_mongodb_destination(self):
        path = os.path.join(self.db_dir.name, "local.db")
        write_legacy_db(path)
        with self.assertRaises(StoreError):
            migrate.migrate_sqlite(path, object(), backup_dir=os.path.join(self.db_dir.name, "b"))


# ============================================================== API
@unittest.skipUnless(HAVE_CLIENT, "fastapi TestClient (httpx) not installed")
class TestStorageApi(EnvSandbox):
    def setUp(self):
        super().setUp()
        self.db_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.db_dir.cleanup)
        env = mock.patch.dict(os.environ, {"BRAND_HUNTER_DB": os.path.join(self.db_dir.name, "local.db")})
        env.start()
        self.addCleanup(env.stop)
        self.client = TestClient(app_module.app)
        local = mock.patch.multiple(app_module, SETTINGS_ALLOWED_CLIENTS={"testclient"}, SETTINGS_ALLOWED_HOSTS={"testserver"})
        local.start()
        self.addCleanup(local.stop)
        self.mongo = MongoStore(mongomock.MongoClient(), "bih_api")
        store_mod.set_store(None)
        self.addCleanup(store_mod.set_store, None)
        self.addCleanup(store_mod.close_all)       # runs before the temp directory is removed (LIFO)

    def test_only_local_requests_may_touch_storage(self):
        with mock.patch.multiple(app_module, SETTINGS_ALLOWED_CLIENTS={"127.0.0.1"}):
            for method, path in (("get", "/api/storage"), ("delete", "/api/storage")):
                self.assertEqual(getattr(self.client, method)(path).status_code, 403)
            self.assertEqual(self.client.put("/api/storage", json={"uri": "mongodb://x"}).status_code, 403)
            self.assertEqual(self.client.post("/api/storage/test", json={}).status_code, 403)
        self.assertEqual(self.client.put("/api/storage", json={"uri": "mongodb://x"}, headers={"Origin": "https://evil.example"}).status_code, 403)

    def test_status_test_save_import_and_reset(self):
        with mock.patch.object(mongostore, "connect_mongo", return_value=self.mongo) as connect:
            st = self.client.get("/api/storage").json()
            self.assertEqual((st["configured"], st["active"], st["connected"], st["explicit"]), ("mongodb", "mongodb", True, False))
            connect.assert_called_with(DEFAULT_MONGODB_URI, None)
            self.assertEqual(st["legacy"], [])
            self.assertEqual(self.client.post("/api/storage/migrate", json={"direction": "from_sqlite"}).status_code, 400)  # nothing to import
            self.assertEqual(self.client.post("/api/storage/migrate", json={"direction": "to_sqlite"}).status_code, 400)    # SQLite is gone

        self.assertEqual(self.client.put("/api/storage", json={"uri": "http://nope"}).status_code, 400)
        uri = "mongodb://bob:TopSecret@db.example:27017/hunterdb"
        bad = {"ok": False, "message": "ServerSelectionTimeoutError: db.example:27017 timed out"}
        with mock.patch.object(app_module, "check_connection", return_value=bad):
            r = self.client.put("/api/storage", json={"uri": uri})
            self.assertEqual(r.status_code, 400)
            self.assertIn("timed out", r.json()["detail"])
        self.assertIsNone(config.get("MONGODB_URI"))                                                 # a broken URI is never saved

        write_legacy_db(os.path.join(self.db_dir.name, "local.db"))                                   # a legacy file to import
        good = {"ok": True, "message": "Connected to MongoDB 8.2.1. Database 'hunterdb' is writable.", "version": "8.2.1", "db": "hunterdb"}
        with mock.patch.object(app_module, "check_connection", return_value=good), \
                mock.patch.object(mongostore, "connect_mongo", return_value=self.mongo):
            r = self.client.put("/api/storage", json={"uri": uri, "db": ""})
            self.assertEqual(r.status_code, 200)
            self.assertNotIn("TopSecret", r.text)
            status = r.json()["status"]
            self.assertEqual((status["configured"], status["explicit"], status["uri"]["hosts"], status["uri"]["database"]),
                             ("mongodb", True, ["db.example:27017"], "hunterdb"))
            self.assertEqual(status["legacy"][0]["counts"]["hunts"], 2)
            self.assertNotIn("TopSecret", self.client.get("/api/storage").text)
            self.assertNotIn("TopSecret", self.client.get("/api/settings/keys").text)               # settings page never leaks it either

            self.assertEqual(self.client.get("/api/hunts").json()["hunts"], [])
            with mock.patch.object(config, "PROJECT_ROOT", self.db_dir.name):                       # backups go to the temp dir
                m = self.client.post("/api/storage/migrate", json={"direction": "from_sqlite"}).json()
            self.assertTrue(m["ok"], m)
            self.assertEqual(m["copied"]["hunts"], 2)
            self.assertEqual(m["status"]["stats"]["hunts"], 2)
            self.assertTrue(m["reports"][0]["backup"]["path"].startswith(self.db_dir.name))
            self.assertEqual(sorted(h["id"] for h in self.client.get("/api/hunts").json()["hunts"]), ["h1", "h2"])
            self.assertTrue(os.path.isfile(os.path.join(self.db_dir.name, "local.db")))            # never deleted

            back = self.client.delete("/api/storage").json()
            self.assertEqual((back["configured"], back["explicit"]), ("mongodb", False))

    def test_unreachable_mongodb_gives_503_not_a_crash(self):
        def down(uri, db=None):
            raise StoreUnavailable("MongoDB is not reachable: ServerSelectionTimeoutError")

        config.save_keys({"MONGODB_URI": "mongodb://down.example:27017"})
        with mock.patch.object(mongostore, "connect_mongo", side_effect=down):
            r = self.client.get("/api/hunts")
            self.assertEqual(r.status_code, 503)
            self.assertIn("not reachable", r.json()["detail"])
            st = self.client.get("/api/storage").json()
            self.assertEqual((st["configured"], st["connected"]), ("mongodb", False))
            self.assertIn("not reachable", st["error"])

    def test_hunt_still_completes_when_storage_is_down(self):
        def down(uri, db=None):
            raise StoreUnavailable("MongoDB is not reachable: ServerSelectionTimeoutError")

        fake = {"target": "adani.com", "depth": "quick", "brand": {"icons": [], "allowlist": ["adani.com"]}, "stats": {"high_risk": 0},
                "candidates": [], "queries": {}, "dorks": {}, "errors": []}
        config.save_keys({"MONGODB_URI": "mongodb://down.example:27017"})
        with mock.patch.object(mongostore, "connect_mongo", side_effect=down), mock.patch.object(app_module, "run_hunt", return_value=fake):
            jid = self.client.post("/api/hunt", json={"target": "adani.com", "depth": "quick"}).json()["job_id"]
            for _ in range(100):
                job = self.client.get(f"/api/hunt/{jid}").json()
                if job["status"] != "running":
                    break
                time.sleep(0.05)
        self.assertEqual(job["status"], "done")                                                      # the result is not lost
        self.assertIn("Could not save to history", " ".join(job["result"]["errors"]))

    def test_scheduler_claims_before_starting(self):
        store_mod.set_store(self.mongo)
        wid = self.mongo.watch_add("paypal.com", "quick", 6, 45, "", [])
        started = []
        with mock.patch.object(app_module, "_start_watch_hunt", side_effect=lambda w: started.append(w["brand"]) or "j1"):
            self.assertEqual(app_module.scheduler_tick(), ["paypal.com"])
            self.assertEqual(app_module.scheduler_tick(), [])                                        # claimed: not started twice
            # a second app instance racing for the same due hunt loses the claim
            self.mongo.watch_update(wid, last_run=time.time() - 7 * 3600, last_status="ok")
            self.assertTrue(self.mongo.watch_claim(wid, time.time() - 6 * 3600))
            self.assertEqual(app_module.scheduler_tick(), [])
        with mock.patch.object(app_module, "_start_watch_hunt", side_effect=app_module.HTTPException(status_code=429, detail="busy")):
            self.mongo.watch_update(wid, last_run=time.time() - 7 * 3600, last_status="ok")
            self.assertEqual(app_module.scheduler_tick(), [])
            w = self.mongo.watch_get(wid)
            self.assertEqual(w["last_status"], "ok")                                                 # busy server: claim is released
            self.assertLess(w["last_run"], time.time() - 6 * 3600)


if __name__ == "__main__":
    unittest.main()
