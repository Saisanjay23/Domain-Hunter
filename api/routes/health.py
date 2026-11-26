"""Index page, health, configured sources, feeds, and OS browser launcher routes."""

import os
import time
import webbrowser

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from api.schemas import LaunchEnginesRequest
from api.services.image_inspector import is_http_url
from core import feeds as feeds_mod
from api.deps import require_local
from core import config as core_config, source_events
from core.config import sources_status
from core.health import check_sources

router = APIRouter()

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STATIC_DIR = os.path.join(PROJECT_ROOT, "web", "static")
MAX_LAUNCH_URLS = 40


@router.get("/api/health")
def api_health():
    return {"status": "ok", "service": "Brand Impersonation Hunter"}


@router.get("/api/sources")
def api_sources():
    """Which threat-intel sources are configured (never returns key values)."""
    return {"sources": sources_status()}


@router.get("/api/sources/health")
def api_sources_health(force: bool = False):
    """Availability of every free source (one cheap probe each, cached 5 min) and configuration of keyed ones."""
    return check_sources(force=force)


@router.get("/api/sources/events")
def api_source_events(hours: float = 72):
    """Skipped / limited / failed source calls from recent runs (shown on Settings > API keys, never on results)."""
    paid = [m["name"] for m in core_config.SOURCES.values() if m.get("paid")]
    return {**source_events.summary(hours), "free_only": core_config.free_only(), "paid_sources": paid}


@router.delete("/api/sources/events", dependencies=[Depends(require_local)])
def api_source_events_clear(source: str = ""):
    source_events.clear(source or None)
    return {"cleared": source or "all"}


@router.get("/api/feeds")
def api_feeds():
    return {"feeds": feeds_mod.feeds_status()}


@router.post("/api/launch-engines")
def api_launch_engines(req: LaunchEnginesRequest):
    """Opens validated http(s) search URLs in the system browser."""
    clean_urls = [u.strip() for u in (req.urls or []) if u and is_http_url(u.strip())]
    if not clean_urls:
        raise HTTPException(status_code=400, detail="No valid HTTP(S) URLs provided.")
    clean_urls = clean_urls[:MAX_LAUNCH_URLS]

    opened = 0
    use_shell = hasattr(os, "startfile")
    for u in clean_urls:
        try:
            if use_shell:
                os.startfile(u)
            else:
                webbrowser.open_new_tab(u)
            opened += 1
            if len(clean_urls) > 1:
                time.sleep(0.12)
        except Exception:
            continue
    return {"status": "ok" if opened else "error", "opened": opened, "mode": "shell" if use_shell else "webbrowser"}


@router.get("/", response_class=FileResponse)
def serve_index():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if not os.path.isfile(index_path):
        raise HTTPException(status_code=404, detail="Web UI index.html not found")
    return FileResponse(index_path, headers={"Cache-Control": "no-cache"})


@router.get("/favicon.ico", response_class=FileResponse)
def serve_favicon():
    fav_path = os.path.join(STATIC_DIR, "favicon.ico")
    if not os.path.isfile(fav_path):
        raise HTTPException(status_code=404, detail="Favicon not found")
    return FileResponse(fav_path, media_type="image/x-icon", headers={"Cache-Control": "no-cache"})
