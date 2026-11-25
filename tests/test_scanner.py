import base64
import codecs
import unittest
from io import BytesIO

import mmh3
from PIL import Image

from core.hasher import mmh3_hash, analyze_icon_bytes, is_image_bytes, is_svg, sniff_image_format, phash_hash
from core.query_gen import generate_search_queries, build_multi_hash_queries


def _png(color=(255, 0, 0, 255), size=(16, 16), mode="RGBA", fmt="PNG"):
    img = Image.new(mode, size, color=color)
    buf = BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()


class TestHasher(unittest.TestCase):
    def setUp(self):
        self.test_png_bytes = _png()

    def test_hashes_generated(self):
        analysis = analyze_icon_bytes(self.test_png_bytes)
        self.assertIsInstance(analysis["mmh3"], int)
        self.assertEqual(len(analysis["md5"]), 32)
        self.assertEqual(len(analysis["sha256"]), 64)
        self.assertIsNotNone(analysis["phash"])
        self.assertEqual(analysis["format"], "PNG")
        self.assertEqual(analysis["dimensions"], "16x16")

    def test_mmh3_matches_shodan_reference_algorithm(self):
        # Shodan: mmh3.hash(codecs.encode(favicon, "base64")) - RFC 2045, 76-char lines + trailing newline
        data = bytes(range(256)) * 3
        self.assertEqual(mmh3_hash(data), mmh3.hash(codecs.encode(data, "base64")))
        self.assertEqual(mmh3_hash(data), mmh3.hash(base64.encodebytes(data)))
        self.assertTrue(-(2 ** 31) <= mmh3_hash(data) < 2 ** 31)

    def test_svg_detection_rejects_xml_error_pages(self):
        svg = b'<?xml version="1.0"?>\n<!-- comment -->\n<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 32"></svg>'
        s3_error = b'<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code></Error>'
        self.assertTrue(is_svg(svg))
        self.assertFalse(is_svg(s3_error))
        self.assertFalse(is_image_bytes(s3_error))
        self.assertEqual(analyze_icon_bytes(svg)["dimensions"], "64x32")

    def test_html_and_empty_are_not_images(self):
        self.assertFalse(is_image_bytes(b""))
        self.assertFalse(is_image_bytes(b"   \n<!DOCTYPE html><html><body>Not found</body></html>"))
        self.assertFalse(is_image_bytes(b'{"error": "not found"}'))

    def test_magic_bytes(self):
        self.assertEqual(sniff_image_format(_png(fmt="ICO", mode="RGBA", size=(16, 16))), "ICO")
        self.assertEqual(sniff_image_format(_png(fmt="GIF", mode="RGB", color=(1, 2, 3))), "GIF")
        self.assertEqual(sniff_image_format(b"RIFF\x00\x00\x00\x00WEBPVP8 "), "WEBP")

    def test_phash_transparency_flattened_on_white(self):
        # A transparent image and the same image on white must be visually identical
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        for x in range(16, 48):
            for y in range(16, 48):
                img.putpixel((x, y), (200, 0, 0, 255))
        buf = BytesIO()
        img.save(buf, format="PNG")
        flat = Image.new("RGB", (64, 64), (255, 255, 255))
        flat.paste(img, mask=img.split()[3])
        buf2 = BytesIO()
        flat.save(buf2, format="JPEG", quality=95)
        self.assertEqual(phash_hash(buf.getvalue()), phash_hash(buf2.getvalue()))


class TestQueryGeneration(unittest.TestCase):
    def test_query_generation(self):
        icons = [
            {
                "url": "https://example.com/favicon.ico",
                "kind": "favicon",
                "mmh3": -12345678,
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "phash": "ffff0000ffff0000",
            }
        ]
        queries = generate_search_queries(icons)
        self.assertIn('icon_hash="-12345678"', queries["fofa"])
        self.assertIn('http.favicon.hash:-12345678', queries["shodan"])
        self.assertIn(
            'host.services.endpoints.http.favicons.hash_md5: "d41d8cd98f00b204e9800998ecf8427e" '
            'or web.endpoints.http.favicons.hash_md5: "d41d8cd98f00b204e9800998ecf8427e"',
            queries["censys"],
        )
        self.assertIn(
            'web.endpoints.http.favicons.hash_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"',
            queries["censys"],
        )
        self.assertIn("hash:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", queries["urlscan"])
        self.assertNotIn("zoomeye", queries)
        self.assertNotIn("hunter", queries)
        self.assertNotIn("netlas", queries)

    def test_logos_only_go_to_urlscan(self):
        icons = [
            {"kind": "favicon", "mmh3": 1, "md5": "a" * 32, "sha256": "1" * 64},
            {"kind": "logo", "mmh3": 2, "md5": "b" * 32, "sha256": "2" * 64},
        ]
        q = generate_search_queries(icons)
        self.assertEqual(q["combined"]["fofa"], 'icon_hash="1"')
        self.assertEqual(q["combined"]["shodan"], "http.favicon.hash:1")
        self.assertNotIn("b" * 32, q["combined"]["censys"])
        self.assertEqual(q["combined"]["urlscan"], f"hash:({'1' * 64} OR {'2' * 64})")
        self.assertEqual(len(q["fofa"]), 1)

    def test_subdomain_icons_excluded_from_master(self):
        icons = [
            {"kind": "favicon", "mmh3": 1, "md5": "a" * 32, "sha256": "1" * 64},
            {"kind": "subdomain", "mmh3": 3, "md5": "c" * 32, "sha256": "3" * 64},
        ]
        q = generate_search_queries(icons)
        self.assertEqual(q["combined"]["shodan"], "http.favicon.hash:1")
        self.assertIn('icon_hash="3"', q["fofa"])  # still listed individually
        self.assertEqual(q["hash_counts"]["excluded_subdomain_icons"], 1)

    def test_multi_hash_combined(self):
        icons = [
            {"mmh3": 1, "md5": "a" * 32, "sha256": "1" * 64},
            {"mmh3": -2, "md5": "b" * 32, "sha256": "2" * 64},
            {"mmh3": 1, "md5": "a" * 32, "sha256": "1" * 64},
        ]
        c = generate_search_queries(icons)["combined"]
        self.assertEqual(c["fofa"], '(icon_hash="1" || icon_hash="-2")')
        self.assertEqual(c["shodan"], "http.favicon.hash:1,-2")
        self.assertEqual(
            c["censys"],
            f'host.services.endpoints.http.favicons.hash_md5: {{"{"a" * 32}", "{"b" * 32}"}} '
            f'or web.endpoints.http.favicons.hash_md5: {{"{"a" * 32}", "{"b" * 32}"}}',
        )

    def test_build_multi_hash_queries(self):
        q = build_multi_hash_queries(["5", 6, "x", 5], ["A" * 32], ["F" * 64])
        self.assertEqual(q["fofa"], '(icon_hash="5" || icon_hash="6")')
        self.assertEqual(q["shodan"], "http.favicon.hash:5,6")
        self.assertIn('"' + "a" * 32 + '"', q["censys"])
        self.assertEqual(q["urlscan"], "hash:" + "f" * 64)
        self.assertEqual(build_multi_hash_queries([]), {})


if __name__ == "__main__":
    unittest.main()
