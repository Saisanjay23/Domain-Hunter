"""MongoDB connection-string helpers that need no driver (so importing them never loads pymongo)."""

from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlsplit

DEFAULT_DB = "brand_hunter"


def _userinfo(uri: str) -> List[str]:
    netloc = urlsplit(uri).netloc
    if "@" not in netloc:
        return []
    raw = netloc.rsplit("@", 1)[0]
    parts = [raw] + raw.split(":", 1)
    return [p for p in {*parts, *(unquote(p) for p in parts)} if p]


def redact(message: str, uri: str) -> str:
    """Removes the connection string and its credentials from a message."""
    out = str(message).replace(uri, "mongodb://***")
    for secret in sorted(_userinfo(uri), key=len, reverse=True):
        out = out.replace(secret, "***")
    return out


def describe_uri(uri: str) -> Dict[str, Any]:
    """Host list, database and whether credentials are present: safe to show in the UI."""
    parts = urlsplit(uri)
    hosts = parts.netloc.rsplit("@", 1)[-1].split(",")
    return {"srv": parts.scheme == "mongodb+srv", "hosts": hosts, "database": parts.path.strip("/") or None,
            "has_credentials": "@" in parts.netloc}


def resolve_db_name(uri: str, db_name: Optional[str] = None) -> str:
    return db_name or describe_uri(uri)["database"] or DEFAULT_DB
