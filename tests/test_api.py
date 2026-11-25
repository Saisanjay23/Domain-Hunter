import base64
import unittest
from io import BytesIO

from PIL import Image

try:
    from fastapi.testclient import TestClient
    import app as app_module
    HAVE_CLIENT = True
except Exception:  # httpx missing
    HAVE_CLIENT = False


def _png_b64():
    buf = BytesIO()
    Image.new("RGBA", (32, 32), (10, 120, 200, 255)).save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


@unittest.skipUnless(HAVE_CLIENT, "fastapi TestClient (httpx) not installed")
class TestApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app_module.app)

    def test_aggregate_ignores_non_hash_numbers(self):
        text = '(icon_hash="-405598701" || icon_hash="356140581") && status_code="200" && port="443"'
        r = self.client.post("/api/aggregate-hashes", json={"input_text": text})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["unique_hashes"], [-405598701, 356140581])
        self.assertEqual(data["queries"]["shodan"], "http.favicon.hash:-405598701,356140581")

    def test_aggregate_md5_sha256_and_int32_range(self):
        text = "123, 99999999999, ab8e8a9201010734eb8fcbe0c57a3243\n" + "a" * 64
        data = self.client.post("/api/aggregate-hashes", json={"input_text": text}).json()
        self.assertEqual(data["unique_hashes"], [123])
        self.assertEqual(data["unique_md5"], ["ab8e8a9201010734eb8fcbe0c57a3243"])
        self.assertEqual(data["unique_sha256"], ["a" * 64])
        self.assertIn("censys", data["queries"])
        self.assertEqual(data["queries"]["urlscan"], "hash:" + "a" * 64)

    def test_aggregate_rejects_garbage(self):
        r = self.client.post("/api/aggregate-hashes", json={"input_text": "no hashes here"})
        self.assertEqual(r.status_code, 400)

    def test_launch_engines_rejects_non_http(self):
        r = self.client.post("/api/launch-engines", json={"urls": ["httpevil.bat", "file:///C:/Windows/notepad.exe", "javascript:alert(1)"]})
        self.assertEqual(r.status_code, 400)

    def test_analyze_image_upload(self):
        r = self.client.post("/api/analyze-image", json={"image_base64": _png_b64(), "compare_phash": "ffffffffffffffff"})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["analysis"]["format"], "PNG")
        self.assertTrue(data["preview_base64"].startswith("data:image/png;base64,"))
        self.assertIsNotNone(data["similarity"])

    def test_analyze_image_rejects_non_image(self):
        r = self.client.post("/api/analyze-image", json={"image_base64": base64.b64encode(b"<html>nope</html>").decode()})
        self.assertEqual(r.status_code, 400)

    def test_bulk_data_uri_and_upload(self):
        r = self.client.post("/api/analyze-images-bulk", json={
            "image_urls": [_png_b64()],
            "images_base64": [{"name": "a.png", "data": _png_b64()}, {"name": "bad.txt", "data": "aGVsbG8="}],
        })
        data = r.json()
        self.assertEqual(data["total_submitted"], 3)
        self.assertEqual(data["successful_count"], 2)
        self.assertEqual(data["unique_mmh3_count"], 1)
        self.assertIn("urlscan", data["master_queries"])

    def test_impersonation(self):
        r = self.client.post("/api/impersonation-dorks", json={"keywords": "paypal.com, AT&T", "include_variants": True})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["keywords"], ["paypal.com", "AT&T"])
        self.assertEqual(data["legit_domains"], ["paypal.com"])
        self.assertTrue(data["include_variants"])
        self.assertIn("all_domains_query", data["master_queries"]["urlscan"])
        self.assertIn("crtsh", data)
        self.assertIn("search_engines", data)

    def test_impersonation_capture_endpoint(self):
        from unittest import mock
        fake = {
            "total_keywords": 1, "total_domains": 1, "total_apex_domains": 1,
            "domains": [{"domain": "paypal-login.xyz", "apex_domain": "paypal-login.xyz", "sources": ["crt.sh"], "title": "", "url": None, "ip": None, "last_seen": "2026-11-24"}],
            "apex_domains": ["paypal-login.xyz"], "source_status": [], "suite": {},
        }
        with mock.patch.object(app_module, "capture_domains_from_keywords", return_value=fake) as m:
            r = self.client.post("/api/impersonation-dorks/capture", json={"keywords": "paypal", "include_variants": True, "use_dns": True})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["total_domains"], 1)
        m.assert_called_once()
        self.assertEqual(self.client.post("/api/impersonation-dorks/capture", json={"keywords": "  "}).status_code, 400)

    def test_scan_validation(self):
        self.assertEqual(self.client.post("/api/scan", json={"target": "  "}).status_code, 400)
        self.assertEqual(self.client.post("/api/scan", json={"target": "x.com", "timeout": 999}).status_code, 422)

    def test_index_served(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("platform-queries-grid", r.text)

    def test_index_ui_structure(self):
        import collections
        from bs4 import BeautifulSoup

        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        soup = BeautifulSoup(r.text, "html.parser")

        ids = [el["id"] for el in soup.find_all(id=True)]
        dups = {k: v for k, v in collections.Counter(ids).items() if v > 1}
        self.assertEqual(dups, {}, f"Duplicate HTML IDs found: {dups}")

        main = soup.find("main", id="content")
        self.assertIsNotNone(main)
        direct_ids = {el.get("id") for el in main.find_all(recursive=False) if el.get("id")}
        expected = {
            "hunt-scan-form", "hunt-empty", "hunt-progress-panel",
            "single-scan-form", "batch-scan-form", "reverse-scan-form",
            "aggregator-scan-form", "impersonation-scan-form",
            "keys-page", "history-page", "watch-page", "storage-page",
            "loading-panel", "hunt-results-section", "results-section",
            "reverse-results-section", "aggregator-results-section",
            "impersonation-results-section",
        }
        self.assertEqual(expected - direct_ids, set())


if __name__ == "__main__":
    unittest.main()
