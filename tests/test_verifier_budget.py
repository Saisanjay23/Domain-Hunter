"""A server that trickles its response must not hold an inspection worker beyond the per-site budget."""
import socket
import threading
import time
import unittest

from core.crawler import FaviconCrawler
from core.verifier import verify_candidate

BRAND = {"domain": "example.com", "title": "Example", "tokens": ["example"], "allowlist": ["example.com"],
         "favicon_mmh3": set(), "favicon_sha256": set(), "any_sha256": set(), "phashes": [], "analytics": set(),
         "words": set(), "cert_org": ""}


class SlowDripServer:
    """Sends valid headers, then one byte every 0.3 s for a long time."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        self.sock.settimeout(0.2)
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            threading.Thread(target=self._drip, args=(conn,), daemon=True).start()

    def _drip(self, conn):
        try:
            conn.recv(4096)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n")
            for _ in range(200):
                if self.stop.is_set():
                    break
                conn.sendall(b"1\r\n<\r\n")
                time.sleep(0.3)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self.stop.set()
        self.sock.close()


class TestSiteBudget(unittest.TestCase):
    def test_slow_server_is_cut_off_at_the_budget(self):
        server = SlowDripServer()
        self.addCleanup(server.close)
        started = time.monotonic()
        ev = verify_candidate(f"127.0.0.1:{server.port}", {}, BRAND, FaviconCrawler(timeout=8), timeout=8, budget=2)
        took = time.monotonic() - started
        self.assertLess(took, 6, f"inspection ran {took:.1f}s with a 2s budget")
        self.assertEqual(ev["http"]["status"], 200)          # the partial response is still reported

    def test_exhausted_budget_makes_no_request(self):
        ev = verify_candidate("127.0.0.1:9", {}, BRAND, FaviconCrawler(timeout=8), timeout=8, budget=0)
        self.assertIsNone(ev["http"])


if __name__ == "__main__":
    unittest.main()
