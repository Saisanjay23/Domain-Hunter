import unittest
from core.matcher import calculate_similarity
from core.query_gen import generate_search_queries


class TestMatcherAndQueries(unittest.TestCase):
    def test_exact_similarity(self):
        phash = "91336ecc89339373"
        res = calculate_similarity(phash, phash)
        self.assertEqual(res["distance"], 0)
        self.assertEqual(res["similarity_percent"], 100.0)
        self.assertEqual(res["confidence"], "EXACT_VISUAL_MATCH")

    def test_similar_variant(self):
        # 1 character difference in hex (1 to 4 bit flips)
        h1 = "91336ecc89339373"
        h2 = "91336eccc9339333"
        res = calculate_similarity(h1, h2)
        self.assertLessEqual(res["distance"], 6)
        self.assertGreaterEqual(res["similarity_percent"], 90.0)
        self.assertEqual(res["confidence"], "HIGH_CONFIDENCE_VARIANT")

    def test_distinct_images(self):
        h1 = "ffffffffffffffff"
        h2 = "0000000000000000"
        res = calculate_similarity(h1, h2)
        self.assertEqual(res["distance"], 64)
        self.assertEqual(res["similarity_percent"], 0.0)
        self.assertEqual(res["confidence"], "DISTINCT")

    def test_expanded_queries(self):
        icons = [
            {
                "url": "https://example.com/logo.png",
                "mmh3": -405598701,
                "md5": "ab8e8a9201010734eb8fcbe0c57a3243",
                "sha256": "54a21e259cf28ad387e23b3329bad593b788220f8b99a125fa5c323bf161ff26",
            }
        ]
        q = generate_search_queries(icons)
        self.assertIn('icon_hash="-405598701"', q["fofa"])
        self.assertIn('http.favicon.hash:-405598701', q["shodan"])
        self.assertTrue(any('favicons.hash_md5: "ab8e8a9201010734eb8fcbe0c57a3243"' in c for c in q["censys"]))
        self.assertIn('web.endpoints.http.favicons.hash_sha256: "54a21e259cf28ad387e23b3329bad593b788220f8b99a125fa5c323bf161ff26"', q["censys"])
        self.assertIn("hash:54a21e259cf28ad387e23b3329bad593b788220f8b99a125fa5c323bf161ff26", q["urlscan"])
        self.assertNotIn("zoomeye", q)
        self.assertNotIn("hunter", q)
        self.assertNotIn("netlas", q)

    def test_missing_phash(self):
        res = calculate_similarity(None, "91336ecc89339373")
        self.assertIsNone(res["distance"])
        self.assertEqual(res["confidence"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
