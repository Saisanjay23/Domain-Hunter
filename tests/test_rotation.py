"""Multiple API keys per source: storage, failover rotation, cooldowns and the settings endpoints."""
import time
import unittest
from unittest import mock

from core import config, keypool, sources
from core.keypool import KeyPool, SourceError, with_rotation
from test_settings import EnvSandbox, HAVE_CLIENT  # noqa: E402 (tests/ is on sys.path under pytest)

if HAVE_CLIENT:
    from fastapi.testclient import TestClient
    import app as app_module

K1, K2, K3 = "key-one-AAAAAAAA1111", "key-two-BBBBBBBB2222", "key-three-CCCCCCC3333"


class FakeResp:
    def __init__(self, status=200, data=None, headers=None):
        self.status_code = status
        self._data = data if data is not None else {}
        self.headers = headers or {}

    def json(self):
        return self._data


class TestKeyStorage(EnvSandbox):
    def test_add_list_primary_remove(self):
        id1 = config.add_key("SHODAN_API_KEY", K1)
        id2 = config.add_key("SHODAN_API_KEY", K2)
        config.add_key("SHODAN_API_KEY", K3)
        self.assertEqual(config.get_list("SHODAN_API_KEY"), [K1, K2, K3])
        self.assertEqual(config.get("SHODAN_API_KEY"), K1)               # single-key callers keep working
        self.assertIn(f"SHODAN_API_KEY={K1},{K2},{K3}", open(self.path).read())

        config.make_primary("SHODAN_API_KEY", id2)
        self.assertEqual(config.get_list("SHODAN_API_KEY"), [K2, K1, K3])
        config.remove_key("SHODAN_API_KEY", id1)
        self.assertEqual(config.get_list("SHODAN_API_KEY"), [K2, K3])

        status = next(f for f in config.key_status() if f["name"] == "SHODAN_API_KEY")
        self.assertEqual([k["position"] for k in status["keys"]], [1, 2])
        self.assertNotIn(K2, repr(status))
        self.assertEqual(status["keys"][0]["hint"], "•••• 2222")

    def test_rejects_duplicates_commas_and_too_many(self):
        config.add_key("FOFA_KEY", K1)
        with self.assertRaises(config.SettingsError):
            config.add_key("FOFA_KEY", K1)
        with self.assertRaises(config.SettingsError):
            config.add_key("FOFA_KEY", "a,b")
        with self.assertRaises(config.SettingsError):
            config.add_key("FOFA_EMAIL", "x@y.z")                      # not a key list
        for i in range(config.MAX_KEYS - 1):
            config.add_key("FOFA_KEY", f"extra-key-{i:04d}xxxx")
        with self.assertRaises(config.SettingsError):
            config.add_key("FOFA_KEY", "one-too-many-key-0000")

    def test_existing_single_key_env_is_a_list_of_one(self):
        with open(self.path, "w") as f:
            f.write(f"CENSYS_PAT={K1}\n")
        self.assertEqual(config.get_list("CENSYS_PAT"), [K1])
        self.assertEqual(config.sources_status()[3]["key_count"], 1)


class TestRotation(EnvSandbox):
    def setUp(self):
        super().setUp()
        config.save_keys({"SHODAN_API_KEY": f"{K1},{K2},{K3}"})
        self.pool = KeyPool()

    def run_with(self, behaviours):
        """behaviours: key -> exception or value; records which keys were tried."""
        tried = []

        def call(key):
            tried.append(key)
            b = behaviours.get(key, "ok")
            if isinstance(b, Exception):
                raise b
            return b

        return tried, call

    def test_failover_on_rate_limit_then_sticks_to_next_key(self):
        tried, call = self.run_with({K1: SourceError("429", kind="rate_limit", retry_after=30)})
        self.assertEqual(with_rotation("shodan", call, pool=self.pool), "ok")
        self.assertEqual(tried, [K1, K2])
        tried.clear()
        with_rotation("shodan", call, pool=self.pool)          # K1 is cooling down: go straight to K2
        self.assertEqual(tried, [K2])
        st = self.pool.status("shodan")
        self.assertEqual(st[config.key_id(K1)]["state"], "cooling")
        self.assertLessEqual(st[config.key_id(K1)]["available_in"], 31)
        self.assertEqual(st[config.key_id(K2)]["state"], "active")
        self.assertEqual(st[config.key_id(K3)]["state"], "standby")

    def test_quota_auth_and_forbidden_are_rotated(self):
        tried, call = self.run_with({K1: SourceError("q", kind="quota"), K2: SourceError("bad", kind="auth")})
        self.assertEqual(with_rotation("shodan", call, pool=self.pool), "ok")
        self.assertEqual(tried, [K1, K2, K3])
        st = self.pool.status("shodan")
        self.assertEqual(st[config.key_id(K1)]["state"], "exhausted")
        self.assertEqual(st[config.key_id(K2)]["state"], "invalid")

    def test_query_errors_are_not_rotated(self):
        tried, call = self.run_with({K1: SourceError("syntax error")})
        with self.assertRaises(SourceError):
            with_rotation("shodan", call, pool=self.pool)
        self.assertEqual(tried, [K1])
        self.assertEqual(self.pool.status("shodan")[config.key_id(K1)]["state"], "active")

    def test_all_keys_paused_message_and_reset(self):
        err = SourceError("429", kind="rate_limit", retry_after=120)
        tried, call = self.run_with({K1: err, K2: err, K3: err})
        with self.assertRaises(SourceError) as ctx:
            with_rotation("shodan", call, pool=self.pool)
        self.assertIn("3 keys failed", str(ctx.exception))
        with self.assertRaises(SourceError) as ctx:
            with_rotation("shodan", call, pool=self.pool)
        self.assertIn("all 3 keys are paused", str(ctx.exception))
        self.assertIn("available in", str(ctx.exception))
        self.pool.reset("shodan")
        tried.clear()
        with self.assertRaises(SourceError):
            with_rotation("shodan", call, pool=self.pool)
        self.assertEqual(tried, [K1, K2, K3])

    def test_cooldown_expires(self):
        tried, call = self.run_with({K1: SourceError("429", kind="rate_limit", retry_after=1)})
        with_rotation("shodan", call, pool=self.pool)
        with mock.patch.object(keypool.time, "time", return_value=time.time() + 5):
            self.assertEqual(self.pool.usable("shodan")[0], K1)

    def test_anonymous_fallback_for_urlscan(self):
        config.save_keys({"URLSCAN_API_KEY": K1})
        tried, call = self.run_with({K1: SourceError("429", kind="rate_limit")})
        self.assertEqual(with_rotation("urlscan", call, anonymous=lambda: "anon", pool=self.pool), "anon")
        self.assertEqual(with_rotation("shodan", lambda k: "ok", pool=KeyPool()), "ok")
        config.save_keys({"URLSCAN_API_KEY": ""})
        self.assertEqual(with_rotation("urlscan", call, anonymous=lambda: "anon", pool=self.pool), "anon")


class TestClientsRotate(EnvSandbox):
    def setUp(self):
        super().setUp()
        keypool.POOL.reset()

    def tearDown(self):
        keypool.POOL.reset()
        super().tearDown()

    def test_shodan_search_moves_to_second_key_on_429(self):
        config.save_keys({"SHODAN_API_KEY": f"{K1},{K2}"})
        used = []

        def fake_get(url, params=None, headers=None, timeout=None):
            used.append(params["key"])
            if params["key"] == K1:
                return FakeResp(429, {"error": "Rate limit reached"}, {"Retry-After": "10"})
            return FakeResp(200, {"matches": [{"ip_str": "1.2.3.4", "port": 443, "hostnames": ["evil.example"]}]})

        with mock.patch("requests.get", side_effect=fake_get):
            hits = sources.shodan_search("http.favicon.hash:1")
        self.assertEqual(used, [K1, K2])
        self.assertEqual(hits[0]["host"], "evil.example")

    def test_rate_limit_wording_is_not_mistaken_for_quota(self):
        with self.assertRaises(SourceError) as ctx:
            sources._json(FakeResp(429, {"error": "Rate limit reached for requests"}, {"Retry-After": "2"}))
        self.assertEqual(ctx.exception.kind, "rate_limit")
        self.assertEqual(ctx.exception.retry_after, 2.0)
        with self.assertRaises(SourceError) as ctx:
            sources._json(FakeResp(429, {"error": "Monthly quota exceeded"}))
        self.assertEqual(ctx.exception.kind, "quota")
        for code, kind in ((401, "auth"), (402, "quota"), (403, "forbidden"), (500, "other")):
            with self.assertRaises(SourceError) as ctx:
                sources._json(FakeResp(code))
            self.assertEqual(ctx.exception.kind, kind)

    def test_serpapi_out_of_searches_is_quota(self):
        config.save_keys({"SERPAPI_KEY": f"{K1},{K2}"})

        def fake_get(url, params=None, headers=None, timeout=None):
            if params["api_key"] == K1:
                return FakeResp(429, {"error": "Your account has run out of searches."})
            return FakeResp(200, {"visual_matches": [{"link": "https://fake.example/x"}]})

        with mock.patch("requests.get", side_effect=fake_get):
            hits = sources.serpapi_lens("https://brand.example/logo.png")
        self.assertEqual(hits[0]["host"], "fake.example")
        self.assertEqual(keypool.POOL.status("serpapi")[config.key_id(K1)]["state"], "exhausted")

    def test_fofa_invalid_key_rotates(self):
        config.save_keys({"FOFA_KEY": f"{K1},{K2}"})

        def fake_get(url, params=None, headers=None, timeout=None):
            if params["key"] == K1:
                return FakeResp(200, {"error": True, "errmsg": "[-700] 账号无效"})
            return FakeResp(200, {"error": False, "results": [["https://x.example", "9.9.9.9", "443", "x.example", "t", ""]]})

        with mock.patch("requests.get", side_effect=fake_get):
            hits = sources.fofa_search('icon_hash="1"')
        self.assertEqual(hits[0]["host"], "x.example")
        self.assertEqual(keypool.POOL.status("fofa")[config.key_id(K1)]["state"], "invalid")


@unittest.skipUnless(HAVE_CLIENT, "fastapi TestClient (httpx) not installed")
class TestMultiKeyApi(EnvSandbox):
    def setUp(self):
        super().setUp()
        keypool.POOL.reset()
        self.client = TestClient(app_module.app)
        self.local = mock.patch.multiple(app_module, SETTINGS_ALLOWED_CLIENTS={"testclient"}, SETTINGS_ALLOWED_HOSTS={"testserver"})
        self.local.start()

    def tearDown(self):
        self.local.stop()
        keypool.POOL.reset()
        super().tearDown()

    def keys(self, body, name="SHODAN_API_KEY"):
        return next(f for f in body["fields"] if f["name"] == name)["keys"]

    def test_add_reorder_remove_and_no_leaks(self):
        for k in (K1, K2):
            r = self.client.post("/api/settings/keys/add", json={"name": "SHODAN_API_KEY", "value": k})
            self.assertEqual(r.status_code, 200)
            self.assertNotIn(k, r.text)
        keys = self.keys(r.json())
        self.assertEqual([k["state"] for k in keys], ["active", "standby"])
        r = self.client.post("/api/settings/keys/primary", json={"name": "SHODAN_API_KEY", "id": keys[1]["id"]})
        self.assertEqual(self.keys(r.json())[0]["id"], keys[1]["id"])
        r = self.client.post("/api/settings/keys/remove", json={"name": "SHODAN_API_KEY", "id": keys[0]["id"]})
        self.assertEqual(len(self.keys(r.json())), 1)
        self.assertEqual(self.client.post("/api/settings/keys/add", json={"name": "SHODAN_API_KEY", "value": K2}).status_code, 400)
        self.assertEqual(self.client.post("/api/settings/keys/remove", json={"name": "SHODAN_API_KEY", "id": "nope"}).status_code, 400)
        src = {s["id"]: s for s in self.client.get("/api/sources").json()["sources"]}
        self.assertEqual(src["shodan"]["key_count"], 1)

    def test_test_all_marks_failures_and_reset_clears(self):
        config.save_keys({"SHODAN_API_KEY": f"{K1},{K2}"})

        def fake_check(source, values):
            key = values["SHODAN_API_KEY"]
            return {"ok": True, "message": "Key accepted"} if key == K2 else {"ok": False, "message": "HTTP 401: key rejected", "kind": "auth"}

        with mock.patch.object(app_module, "check_key", side_effect=fake_check), mock.patch.object(app_module.time, "sleep") as slept:
            r = self.client.post("/api/settings/keys/test", json={"source": "shodan", "all": True}).json()
        slept.assert_called_once_with(1.1)  # Shodan calls are spaced out
        self.assertEqual(r["message"], "1 of 2 keys working")
        self.assertNotIn(K1, repr(r))
        keys = self.keys(self.client.get("/api/settings/keys").json())
        self.assertEqual(keys[0]["state"], "invalid")
        r = self.client.post("/api/settings/keys/reset", json={"source": "shodan"}).json()
        self.assertEqual(self.keys(r)[0]["state"], "active")

        with mock.patch.object(app_module, "check_key", side_effect=fake_check):
            one = self.client.post("/api/settings/keys/test", json={"source": "shodan", "key_id": config.key_id(K2)}).json()
        self.assertTrue(one["ok"])
        self.assertEqual(self.client.post("/api/settings/keys/test", json={"source": "shodan", "key_id": "zzz"}).status_code, 404)


if __name__ == "__main__":
    unittest.main()
