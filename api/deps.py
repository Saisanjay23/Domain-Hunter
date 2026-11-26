"""Security guards, error redaction, and app-hook resolution for FastAPI routes."""

import sys
from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException, Request

from core import config as core_config
from core.mongouri import redact as redact_uri

SETTINGS_ALLOWED_CLIENTS = {"127.0.0.1", "::1"}
SETTINGS_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}


def app_attr(name: str, default: Any) -> Any:
    """Reads an attribute from the top-level `app` module if present so test patches on `app` take effect."""
    mod = sys.modules.get("app")
    return getattr(mod, name, default) if mod is not None else default


def require_local(request: Request) -> None:
    """Restricts secret/storage endpoints to loopback clients and local Host/Origin headers."""
    allowed_clients = app_attr("SETTINGS_ALLOWED_CLIENTS", SETTINGS_ALLOWED_CLIENTS)
    allowed_hosts = app_attr("SETTINGS_ALLOWED_HOSTS", SETTINGS_ALLOWED_HOSTS)
    client = request.client.host if request.client else ""
    host = (request.headers.get("host") or "").rsplit(":", 1)[0].strip("[]").lower()
    origin = request.headers.get("origin")
    origin_host = (urlparse(origin).hostname or "").lower() if origin else None
    foreign_origin = origin_host is not None and origin_host not in allowed_hosts
    if client not in allowed_clients or host not in allowed_hosts or foreign_origin:
        raise HTTPException(
            status_code=403,
            detail="API keys can only be managed from this machine (http://127.0.0.1 or http://localhost).",
        )


def require_same_origin(request: Request) -> None:
    """Blocks cross-site writes (CSRF / DNS rebinding)."""
    origin = request.headers.get("origin")
    if origin and urlparse(origin).netloc.lower() != (request.headers.get("host") or "").lower():
        raise HTTPException(status_code=403, detail="Cross-site requests are not allowed.")


def safe_error(e: BaseException) -> str:
    """Formats an exception message with any MongoDB credentials redacted."""
    msg = f"{e.__class__.__name__}: {e}"
    uri = core_config.get("MONGODB_URI")
    return redact_uri(msg, uri) if uri else msg
