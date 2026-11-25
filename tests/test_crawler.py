"""Offline crawler tests: the HTTP layer is replaced by an in-memory site map."""
import base64
import unittest
from io import BytesIO

from PIL import Image

from core.crawler import FaviconCrawler, FetchResult, decode_data_uri
from core.domains import registrable_domain, same_organization, normalize_host


def _img(color, fmt="PNG", size=(16, 16)):
    buf = BytesIO()
    Image.new("RGBA", size, color).save(buf, format=fmt)
    return buf.getvalue()


RED, BLUE, GREEN, GREY = _img((255, 0, 0, 255)), _img((0, 0, 255, 255)), _img((0, 255, 0, 255)), _img((9, 9, 9, 255))
ICO = _img((1, 2, 3, 255), fmt="ICO")
SOFT_404 = b"<!DOCTYPE html><html><body>Page not found</body></html>"


class FakeCrawler(FaviconCrawler):
    def __init__(self, site, **kw):
        super().__init__(**kw)
        self.site = site
        self.requested = []

    def _safe_get(self, url, max_bytes=0):
        self.requested.append(url)
        entry = self.site.get(url)
        if entry is None:
            return None
        status, ctype, body, final = (entry + (None,))[:4] if len(entry) == 3 else entry
        return FetchResult(url=final or url, status=status, headers={"content-type": ctype}, content=body)


HOMEPAGE = b"""<!DOCTYPE html><html><head>
<base href="https://www.example.co.uk/assets/">
<link rel="Shortcut Icon" href="img/fav.ico">
<link rel="apple-touch-icon" sizes="180x180" href="/touch.png">
<link rel="icon" href="data:image/png;base64,""" + base64.b64encode(GREEN) + b"""">
<link rel="manifest" href="/site.webmanifest">
<link rel="stylesheet" href="/style.css">
<meta property="og:image" content="https://cdn.example.net/og.png">
</head><body><img class="site-logo" src="/logo.png"></body></html>"""

MANIFEST = b'{"icons": [{"src": "/icon-192.png", "sizes": "192x192"}, {"src": "img/fav.ico", "sizes": "16x16"}]}'


def build_site():
    return {
        "https://example.co.uk/": (200, "text/html", HOMEPAGE, "https://www.example.co.uk/"),
        "https://www.example.co.uk/assets/img/fav.ico": (200, "image/x-icon", ICO),
        "https://www.example.co.uk/touch.png": (200, "image/png", RED),
        "https://www.example.co.uk/site.webmanifest": (200, "application/manifest+json", MANIFEST),
        "https://www.example.co.uk/icon-192.png": (200, "image/png", BLUE),
        # manifest points (relative to manifest URL) at the same bytes via another path
        "https://www.example.co.uk/img/fav.ico": (200, "image/x-icon", ICO),
        # SPA catch-all: /favicon.ico returns HTML with 200
        "https://www.example.co.uk/favicon.ico": (200, "text/html", SOFT_404),
        "https://example.co.uk/favicon.ico": (200, "image/x-icon", ICO),
        "https://cdn.example.net/og.png": (200, "image/png", GREY),
        "https://www.example.co.uk/logo.png": (200, "image/png", _img((5, 50, 200, 255))),
        # subdomain probes
        "https://careers.example.co.uk/favicon.ico": (200, "image/x-icon", _img((7, 7, 7, 255), "ICO")),
        "https://mail.example.co.uk/favicon.ico": (200, "image/x-icon", _img((8, 8, 8, 255), "ICO"), "https://outlook.office365.com/favicon.ico"),
    }


class TestCrawler(unittest.TestCase):
    def scan(self, **kw):
        c = FakeCrawler(build_site(), include_logos=True, probe_subdomains=True, **kw)
        return c, c.scan("Example.co.uk")

    def test_discovery_and_dedup(self):
        c, r = self.scan()
        self.assertEqual(r["domain"], "example.co.uk")
        self.assertEqual(r["resolved_url"], "https://www.example.co.uk/")
        urls = [i["url"] for i in r["icons"]]

        # <base href> honoured, rel tokens are case-insensitive
        self.assertIn("https://www.example.co.uk/assets/img/fav.ico", " ".join(urls + sum((i.get("also_found_at") or [] for i in r["icons"]), [])))
        # data: URI favicon decoded and hashed
        self.assertTrue(any(u.startswith("data:image/png") for u in urls))
        # manifest icons resolved relative to the manifest
        self.assertIn("https://www.example.co.uk/icon-192.png", urls)
        # identical bytes appear once
        shas = [i["sha256"] for i in r["icons"]]
        self.assertEqual(len(shas), len(set(shas)))
        # soft-404 HTML is never reported as an icon
        self.assertNotIn("https://www.example.co.uk/favicon.ico", urls)
        # original (pre-redirect) host fallback is probed too
        self.assertIn("https://example.co.uk/favicon.ico", c.requested)

    def test_kinds_and_primary(self):
        _, r = self.scan()
        primary = [i for i in r["icons"] if i["is_primary"]]
        self.assertEqual(len(primary), 1)
        self.assertEqual(primary[0]["kind"], "favicon")
        self.assertEqual(primary[0]["format"], "ICO")
        logos = [i for i in r["icons"] if i["kind"] == "logo"]
        self.assertEqual({i["url"] for i in logos}, {"https://cdn.example.net/og.png", "https://www.example.co.uk/logo.png"})

    def test_subdomain_probe_uses_psl_and_rejects_off_org_redirects(self):
        c, r = self.scan()
        probed = [u for u in c.requested if "careers." in u]
        self.assertEqual(probed, ["https://careers.example.co.uk/favicon.ico"])
        self.assertFalse(any("careers.co.uk" in u for u in c.requested))
        sub = [i for i in r["icons"] if i["kind"] == "subdomain"]
        self.assertEqual([i["url"] for i in sub], ["https://careers.example.co.uk/favicon.ico"])  # mail -> outlook dropped

    def test_www_and_http_fallback(self):
        site = {
            "https://www.onlywww.com/": (200, "text/html", b'<html><head><link rel="icon" href="/f.png"></head></html>'),
            "https://www.onlywww.com/f.png": (200, "image/png", RED),
        }
        c = FakeCrawler(site)
        r = c.scan("onlywww.com")
        self.assertEqual(r["resolved_url"], "https://www.onlywww.com/")
        self.assertEqual([i["url"] for i in r["icons"]], ["https://www.onlywww.com/f.png"])
        self.assertTrue(r["reachable"])

    def test_unreachable(self):
        c = FakeCrawler({})
        r = c.scan("does-not-exist.invalid")
        self.assertEqual(r["icons"], [])
        self.assertFalse(r["reachable"])

    def test_meta_refresh_followed(self):
        site = {
            "https://refresh.com/": (200, "text/html", b'<html><head><meta http-equiv="Refresh" content="0; URL=/en/"></head></html>'),
            "https://refresh.com/en/": (200, "text/html", b'<html><head><link rel="icon" href="i.png"></head></html>'),
            "https://refresh.com/en/i.png": (200, "image/png", BLUE),
        }
        r = FakeCrawler(site).scan("refresh.com")
        self.assertEqual(r["resolved_url"], "https://refresh.com/en/")
        self.assertIn("https://refresh.com/en/i.png", [i["url"] for i in r["icons"]])

    def test_normalize_target(self):
        c = FaviconCrawler()
        self.assertEqual(c.normalize_target(" 'HTTPS://Www.Example.COM/path?q=1' "), ("www.example.com", "https://www.example.com/path?q=1"))
        self.assertEqual(c.normalize_target("example.com:8443"), ("example.com:8443", "https://example.com:8443/"))
        self.assertEqual(c.normalize_target("example.com."), ("example.com", "https://example.com/"))

    def test_decode_data_uri(self):
        self.assertEqual(decode_data_uri("data:image/png;base64," + base64.b64encode(RED).decode()), RED)
        self.assertEqual(decode_data_uri("data:image/svg+xml,%3Csvg%3E%3C/svg%3E"), b"<svg></svg>")
        self.assertIsNone(decode_data_uri("data:,"))


class TestDomains(unittest.TestCase):
    def test_registrable_domain(self):
        self.assertEqual(registrable_domain("careers.bbc.co.uk"), "bbc.co.uk")
        self.assertEqual(registrable_domain("www.gi-de.com"), "gi-de.com")
        self.assertIsNone(registrable_domain("10.0.0.1"))
        self.assertFalse(same_organization("a.github.io", "b.github.io"))
        self.assertTrue(same_organization("mail.example.com", "www.example.com"))
        self.assertEqual(normalize_host("Bücher.DE."), "xn--bcher-kva.de")


if __name__ == "__main__":
    unittest.main()
