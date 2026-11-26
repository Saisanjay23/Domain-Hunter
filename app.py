"""
Brand Impersonation Hunter: FastAPI application entrypoint.
Routes, schemas, and background services live under api/.
"""

import os
import time

import urllib3
from fastapi import FastAPI, HTTPException, Request  # noqa: F401
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from api.deps import SETTINGS_ALLOWED_CLIENTS, SETTINGS_ALLOWED_HOSTS, safe_error  # noqa: F401
from api.security import security_middleware
from api.routes import cases, datamgmt, health, hunt, impersonation, investigate, scan, scheduler, settings
from api.services.batch_scheduler import ENGINE as BATCH_ENGINE, start_batch_scheduler, stop_batch_scheduler  # noqa: F401
from api.services.image_inspector import (  # noqa: F401
    api_icon,
    build_candidate_result,
    clean_url_string,
    decode_base64_upload,
    extract_candidate_urls,
    extract_hashes_from_text,
    extract_images_from_html,
    fetch_single_candidate,
    is_http_url,
    scan_response,
)
from api.services.jobs import (  # noqa: F401
    HUNT_JOBS,
    HUNT_LOCK,
    SCHEDULER_STATE,
    _finish_watch,
    _finish_watch_safe,
    _run_hunt_job,
    _start_watch_hunt,
    hunt_api_result,
    scheduler_tick,
    start_hunt,
    start_scheduler,
)
from core import alerts as alerts_mod, takedown  # noqa: F401
from core.daily_intel import run_daily_intel  # noqa: F401
from core.hunter import HuntCancelled, run_hunt  # noqa: F401
from core.impersonation import capture_domains_from_keywords  # noqa: F401
from core.sources import check_key  # noqa: F401
from core.store import StoreUnavailable
from favicon_hash import scan_domain  # noqa: F401

check_connection = settings.check_connection

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI(
    title="Brand Impersonation Hunter API",
    description="Enterprise brand impersonation detection, URLScan daily search, WhoisXML monitoring, and favicon/logo threat-intel platform.",
    version="2.0.0",
)

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "static")
os.makedirs(STATIC_DIR, exist_ok=True)
class RevalidatingStatic(StaticFiles):
    """Static assets are always revalidated (ETag / 304), so a UI update is never hidden behind a stale cached file."""

    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache"
        return response


app.mount("/static", RevalidatingStatic(directory=STATIC_DIR), name="static")
app.middleware("http")(security_middleware)

app.include_router(health.router)
app.include_router(scan.router)
app.include_router(hunt.router)
app.include_router(impersonation.router)
app.include_router(investigate.router)
app.include_router(cases.router)
app.include_router(settings.router)
app.include_router(scheduler.router)
app.include_router(datamgmt.router)


@app.exception_handler(StoreUnavailable)
async def _handle_store_unavailable(request: Request, exc: StoreUnavailable):
    return JSONResponse(status_code=503, content={"detail": str(exc)})


app.router.add_event_handler("startup", start_scheduler)
app.router.add_event_handler("startup", start_batch_scheduler)
app.router.add_event_handler("shutdown", stop_batch_scheduler)


def start_server(host: str = "127.0.0.1", port: int = 8080):
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(description="Brand Impersonation Hunter Web UI")
    parser.add_argument("--port", type=int, default=port, help="Port to listen on (default: 8080)")
    parser.add_argument("--host", type=str, default=host, help="Host to listen on (default: 127.0.0.1)")
    args, _ = parser.parse_known_args()

    print("\n=======================================================")
    print("[*] Starting Brand Impersonation Hunter Web UI...")
    print(f"[*] Dashboard URL: http://{args.host}:{args.port}")
    print("=======================================================\n")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    _ = time
    start_server()
