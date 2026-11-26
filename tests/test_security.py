"""Security hardening: SSRF guard on candidate fetches, API rate limiting, security headers and body limits."""
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

import pytest

from core import netguard
from core.crawler import FaviconCrawler


@pytest.fixture(autouse=True)
def fresh_guard():
    netguard.clear_cache()
    with mock.patch.dict(os.environ, {"BRAND_HUNTER_ALLOW_PRIVATE_FETCH": ""}):
        yield
    netguard.clear_cache()


class Hits(BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):
        Hits.hits += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"internal secret")

    def log_message(self, *a):
        pass


@pytest.fixture
def internal_server():
    Hits.hits = 0
    srv = HTTPServer(("127.0.0.1", 0), Hits)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def test_ip_classification():
    for bad in ("127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "::ffff:127.0.0.1", "fd00::1"):
        assert not netguard.is_public_ip(bad), bad
    for good in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
        assert netguard.is_public_ip(good), good


def test_crawler_never_connects_to_internal_addresses(internal_server):
    c = FaviconCrawler(timeout=3)
    assert c._safe_get(f"http://127.0.0.1:{internal_server}/") is None
    assert Hits.hits == 0                                              # refused before any connection


def test_lookalike_dns_pointing_inside_is_blocked(internal_server):
    real = socket.getaddrinfo

    def fake(host, *a, **kw):
        if host == "paypal-login.evil-lookalike.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
        return real(host, *a, **kw)
    with mock.patch.object(socket, "getaddrinfo", side_effect=fake):
        ok, reason = netguard.check_host("paypal-login.evil-lookalike.com")
    assert not ok and "127.0.0.1" in reason


def test_redirect_into_the_internal_network_is_blocked(internal_server):
    import requests
    s = requests.Session()
    s.mount("http://", netguard.PublicOnlyAdapter())
    with pytest.raises(netguard.BlockedAddress):
        s.get(f"http://127.0.0.1:{internal_server}/", timeout=3)
    assert Hits.hits == 0


def test_opt_in_allows_internal_scans(internal_server):
    with mock.patch.dict(os.environ, {"BRAND_HUNTER_ALLOW_PRIVATE_FETCH": "1"}):
        r = FaviconCrawler(timeout=3)._safe_get(f"http://127.0.0.1:{internal_server}/")
    assert r is not None and r.status == 200 and Hits.hits == 1


# ============================================================== HTTP hardening
@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    import app as app_module
    from api import security
    security.reset()
    yield TestClient(app_module.app)
    security.reset()


def test_security_headers(client):
    r = client.get("/api/scheduler/timezones")
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer" and r.headers["cache-control"] == "no-store"
    assert client.get("/").headers["x-frame-options"] == "DENY"


def test_write_rate_limit_and_stricter_destructive_budget(client):
    with mock.patch.dict(os.environ, {"BRAND_HUNTER_RATE_LIMIT": "12"}):
        codes = [client.post("/api/scheduler/parse", json={"text": "paypal.com"}).status_code for _ in range(14)]
        assert codes[:12] == [200] * 12 and codes[12:] == [429, 429]
        r = client.post("/api/scheduler/parse", json={"text": "x"})
        assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
        assert client.get("/api/scheduler/timezones").status_code == 200          # reads are not limited
        data = [client.post("/api/data/domains/md_000000000000/delete", json={"confirm": "x"}).status_code for _ in range(11)]
        assert data.count(429) == 1                                               # 10 per minute for /api/data/


def test_oversized_body_is_refused(client):
    with mock.patch.dict(os.environ, {"BRAND_HUNTER_MAX_BODY_MB": "1"}):
        r = client.post("/api/scheduler/parse", content=b"x" * (1024 * 1024 + 10), headers={"Content-Type": "application/json"})
    assert r.status_code == 413
