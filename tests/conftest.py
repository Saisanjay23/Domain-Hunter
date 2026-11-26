"""Test isolation: every test gets its own (in-memory MongoDB) database and no background scheduler."""
import os
import sys

import pytest

os.environ["BRAND_HUNTER_SCHEDULER"] = "0"
os.environ.setdefault("BRAND_HUNTER_RATE_LIMIT", "0")   # the limiter has its own tests (test_security.py)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True)
def isolated_source_events(tmp_path):
    """Hunts in tests must never write to the real Settings > Source activity log."""
    from core import source_events

    source_events._reset_for_tests(str(tmp_path / "source_events.json"))
    yield


@pytest.fixture(autouse=True)
def clean_caches():
    """Process-wide caches (CT lookups, free-search, matcher) must not leak between tests."""
    from core import discovery, domain_matcher, sources

    discovery.clear_ct_cache()
    sources._FREE_CACHE.clear()
    domain_matcher._match_core.cache_clear()
    yield


@pytest.fixture(autouse=True)
def isolated_store():
    """Every test gets its own in-memory MongoDB (mongomock): never the real server, never shared state."""
    import uuid

    import mongomock

    from core import store
    from core.mongostore import MongoStore

    s = MongoStore(mongomock.MongoClient(), f"bih_test_{uuid.uuid4().hex[:8]}")
    store.set_store(s)
    yield s
    store.set_store(None)
    s.close()
