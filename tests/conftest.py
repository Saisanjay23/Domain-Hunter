"""Test isolation: every test gets its own history database and no background scheduler."""
import os
import sys

import pytest

os.environ["BRAND_HUNTER_SCHEDULER"] = "0"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True)
def isolated_store(tmp_path):
    from core import store

    s = store.Store(str(tmp_path / "test.db"))
    store.set_store(s)
    yield s
    store.set_store(None)
    s.close()
