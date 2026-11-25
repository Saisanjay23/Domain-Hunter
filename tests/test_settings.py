"""API key settings: .env writing, masking, validation, local-only guard and endpoints."""
import os
import tempfile
import unittest
from unittest import mock

from core import config

try:
    from fastapi.testclient import TestClient
    import app as app_module
    HAVE_CLIENT = True
except Exception:
    HAVE_CLIENT = False

SECRET = "dummy-test-key-12345678wxyz"


class EnvSandbox(unittest.TestCase):
    """Points config at a temporary .env and restores the environment afterwards."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, ".env")
        self.patches = [mock.patch.object(config, "ENV_FILE", self.path), mock.patch.dict(os.environ, {}, clear=False)]
        for p in self.patches:
            p.start()
        for name in config.KEY_FIELDS:
            os.environ.pop(name, None)
            config._from_file.discard(name)
        config._loaded_mtime = None

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        for name in config.KEY_FIELDS:
            config._from_file.discard(name)
        config._loaded_mtime = None
        self.tmp.cleanup()


class TestSaveKeys(EnvSandbox):
    def test_writes_updates_removes_and_keeps_other_lines(self):
        with open(self.path, "w") as f:
            f.write("# my notes\nOTHER_SETTING=keep-me\nSHODAN_API_KEY=\n")
        changed = config.save_keys({"SHODAN_API_KEY": SECRET, "FOFA_KEY": "fofa1234567890"})
        self.assertEqual(sorted(changed), ["FOFA_KEY", "SHODAN_API_KEY"])
        text = open(self.path).read()
        self.assertIn("# my notes", text)
        self.assertIn("OTHER_SETTING=keep-me", text)
        self.assertIn(f"SHODAN_API_KEY={SECRET}", text)
        self.assertEqual(config.get("SHODAN_API_KEY"), SECRET)   # applied immediately

        config.save_keys({"SHODAN_API_KEY": ""})                    # remove
        self.assertIsNone(config.get("SHODAN_API_KEY"))
        self.assertEqual(config.get("FOFA_KEY"), "fofa1234567890")
        self.assertEqual(config.save_keys({"FOFA_KEY": "fofa1234567890"}), [])  # unchanged value

    def test_rejects_unknown_names_and_bad_values(self):
        with self.assertRaises(config.SettingsError):
            config.save_keys({"PATH": "x"})
        with self.assertRaises(config.SettingsError):
            config.save_keys({"SHODAN_API_KEY": "abc\nINJECTED=1"})
        with self.assertRaises(config.SettingsError):
            config.save_keys({"SHODAN_API_KEY": "has space"})
        self.assertFalse(os.path.exists(self.path))

    def test_system_environment_is_read_only(self):
        os.environ["CENSYS_PAT"] = "from-system-env-123456"
        status = {f["name"]: f for f in config.key_status()}
        self.assertEqual(status["CENSYS_PAT"]["origin"], "system")
        self.assertFalse(status["CENSYS_PAT"]["editable"])
        with self.assertRaises(config.SettingsError):
            config.save_keys({"CENSYS_PAT": "other-value-1234567"})

    def test_status_never_reveals_values(self):
        config.save_keys({"SHODAN_API_KEY": SECRET, "FOFA_EMAIL": "analyst@example.com", "SERPAPI_KEY": "short"})
        status = {f["name"]: f for f in config.key_status()}
        self.assertEqual(status["SHODAN_API_KEY"]["hint"], "•••• wxyz")
        self.assertEqual(status["SERPAPI_KEY"]["hint"], "••••")   # too short to show any characters
        self.assertNotIn("analyst@example.com", repr(status))
        self.assertNotIn(SECRET, repr(status))
        self.assertEqual(status["SHODAN_API_KEY"]["origin"], "file")


@unittest.skipUnless(HAVE_CLIENT, "fastapi TestClient (httpx) not installed")
class TestSettingsApi(EnvSandbox):
    def setUp(self):
        super().setUp()
        self.client = TestClient(app_module.app)

    def local(self):
        return mock.patch.multiple(app_module, SETTINGS_ALLOWED_CLIENTS={"testclient"}, SETTINGS_ALLOWED_HOSTS={"testserver"})

    def test_non_local_requests_are_refused(self):
        # TestClient's peer is "testclient", which is not a loopback address.
        self.assertEqual(self.client.get("/api/settings/keys").status_code, 403)
        self.assertEqual(self.client.put("/api/settings/keys", json={"values": {"SHODAN_API_KEY": SECRET}}).status_code, 403)
        self.assertFalse(os.path.exists(self.path))

    def test_foreign_origin_is_refused(self):
        with self.local():
            r = self.client.put("/api/settings/keys", json={"values": {"SHODAN_API_KEY": SECRET}},
                                headers={"Origin": "https://evil.example"})
        self.assertEqual(r.status_code, 403)
        self.assertFalse(os.path.exists(self.path))

    def test_save_status_and_remove(self):
        with self.local():
            r = self.client.put("/api/settings/keys", json={"values": {"SHODAN_API_KEY": SECRET}})
            self.assertEqual(r.status_code, 200)
            self.assertNotIn(SECRET, r.text)
            self.assertEqual(r.json()["changed"], ["SHODAN_API_KEY"])
            body = self.client.get("/api/settings/keys").json()
            self.assertNotIn(SECRET, repr(body))
            shodan = next(f for f in body["fields"] if f["name"] == "SHODAN_API_KEY")
            self.assertTrue(shodan["set"])
            src = {s["id"]: s for s in self.client.get("/api/sources").json()["sources"]}
            self.assertEqual(src["shodan"]["mode"], "key")
            self.assertEqual(self.client.put("/api/settings/keys", json={"values": {"BAD": "x"}}).status_code, 400)
            self.client.put("/api/settings/keys", json={"values": {"SHODAN_API_KEY": ""}})
            src = {s["id"]: s for s in self.client.get("/api/sources").json()["sources"]}
            self.assertEqual(src["shodan"]["mode"], "off")

    def test_test_endpoint_uses_typed_value(self):
        with self.local(), mock.patch.object(app_module, "check_key", return_value={"ok": True, "message": "Key accepted"}) as ck:
            r = self.client.post("/api/settings/keys/test", json={"source": "shodan", "values": {"SHODAN_API_KEY": SECRET}})
            self.assertEqual(r.json(), {"ok": True, "message": "Key accepted"})
            ck.assert_called_once_with("shodan", {"SHODAN_API_KEY": SECRET})
            self.assertEqual(self.client.post("/api/settings/keys/test", json={"source": "nope"}).status_code, 400)


class TestCheckKey(EnvSandbox):
    def test_messages_never_contain_key(self):
        from core import sources

        class R:
            status_code = 200

            def json(self):
                return {"plan": "dev", "query_credits": 0}

        with mock.patch("requests.get", return_value=R()):
            out = sources.check_key("shodan", {"SHODAN_API_KEY": SECRET})
        self.assertTrue(out["ok"])
        self.assertIn("paid membership", out["message"])
        self.assertNotIn(SECRET, out["message"])
        self.assertEqual(sources.check_key("fofa")["message"], "no key entered")


if __name__ == "__main__":
    unittest.main()
