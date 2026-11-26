"""Local-only API key settings, rotation control, and storage backend routes."""

from importlib.metadata import PackageNotFoundError, version as _version
import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException

from api.deps import app_attr, require_local
from api.schemas import (
    AddKeyRequest,
    KeyRefRequest,
    ResetRequest,
    SaveKeysRequest,
    StorageUriRequest,
    TestKeyRequest,
)
from core import config as core_config
from core.config import (
    KEY_FIELDS,
    SOURCE_LINKS,
    SOURCES,
    SettingsError,
    add_key,
    free_only,
    get_list,
    key_id,
    key_status,
    make_primary,
    remove_key,
    save_keys,
)
from core.keypool import POOL, SourceError as PoolError
from core.mongouri import describe_uri, resolve_db_name
from core.sources import check_key as core_check_key
from core.store import DEFAULT_MONGODB_URI, StoreUnavailable, configured_uri, get_store

router = APIRouter()


def settings_payload() -> Dict[str, Any]:
    fields = key_status()
    for f in fields:
        if f.get("multi"):
            status = POOL.status(f["source"])
            for k in f["keys"]:
                k.update(status.get(k["id"], {"state": "standby", "uses": 0}))
    return {
        "fields": fields,
        "sources": [
            {
                "id": k, "name": m["name"], "does": m["does"], "key_required": m["key_required"],
                "env": m["env"][0], "link": SOURCE_LINKS.get(k), "paid": bool(m.get("paid")),
                "free_mode_off": bool(m.get("paid")) and free_only(),
            }
            for k, m in SOURCES.items()
        ],
    }


def _settings_call(fn, *args):
    try:
        fn(*args)
    except SettingsError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return settings_payload()


@router.get("/api/settings/keys", dependencies=[Depends(require_local)])
def api_get_keys():
    return settings_payload()


@router.put("/api/settings/keys", dependencies=[Depends(require_local)])
def api_save_keys(req: SaveKeysRequest):
    try:
        changed = save_keys(req.values)
    except SettingsError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"changed": changed, **settings_payload()}


@router.post("/api/settings/keys/add", dependencies=[Depends(require_local)])
def api_add_key(req: AddKeyRequest):
    return _settings_call(add_key, req.name, req.value)


@router.post("/api/settings/keys/remove", dependencies=[Depends(require_local)])
def api_remove_key(req: KeyRefRequest):
    payload = _settings_call(remove_key, req.name, req.id)
    POOL.reset(KEY_FIELDS[req.name]["source"], req.id)
    return payload


@router.post("/api/settings/keys/primary", dependencies=[Depends(require_local)])
def api_primary_key(req: KeyRefRequest):
    return _settings_call(make_primary, req.name, req.id)


@router.post("/api/settings/keys/reset", dependencies=[Depends(require_local)])
def api_reset_keys(req: ResetRequest):
    if req.source is not None and req.source not in SOURCES:
        raise HTTPException(status_code=400, detail="Unknown source.")
    POOL.reset(req.source)
    return settings_payload()


def _test_saved(source: str, env: str, value: str) -> Dict[str, Any]:
    checker = app_attr("check_key", core_check_key)
    result = checker(source, {env: value})
    kid = key_id(value)
    POOL.reset(source, kid)
    if not result["ok"] and result.get("kind") in ("auth", "quota", "rate_limit", "forbidden"):
        POOL.mark_failure(source, value, PoolError(result["message"], kind=result["kind"]))
    return {"id": kid, **{k: v for k, v in result.items() if k != "kind"}}


@router.post("/api/settings/keys/test", dependencies=[Depends(require_local)])
def api_test_key(req: TestKeyRequest):
    if req.source not in SOURCES:
        raise HTTPException(status_code=400, detail="Unknown source.")
    env = SOURCES[req.source]["env"][0]
    saved = get_list(env)
    checker = app_attr("check_key", core_check_key)
    time_mod = app_attr("time", time)
    if req.all:
        results = []
        for i, v in enumerate(saved):
            if i and req.source == "shodan":
                time_mod.sleep(1.1)
            results.append(_test_saved(req.source, env, v))
        if not results:
            only = checker(req.source, {})
            return {"ok": only["ok"], "message": only["message"], "results": []}
        good = sum(1 for r in results if r["ok"])
        return {"ok": good > 0, "message": f"{good} of {len(results)} keys working", "results": results}
    if req.key_id:
        value = next((v for v in saved if key_id(v) == req.key_id), None)
        if value is None:
            raise HTTPException(status_code=404, detail="Key not found.")
        return _test_saved(req.source, env, value)
    result = checker(req.source, {k: v for k, v in req.values.items() if v})
    return {k: v for k, v in result.items() if k != "kind"}


def check_connection(uri: str, db_name: Optional[str] = None) -> Dict[str, Any]:
    from core.mongostore import check_connection as _check
    return _check(uri, db_name)


def _pkg_version(name: str) -> str:
    try:
        return _version(name)
    except PackageNotFoundError:
        return "not installed"


def storage_status() -> Dict[str, Any]:
    uri, explicit = configured_uri()
    name = core_config.get("MONGODB_DB")
    field = next(f for f in key_status() if f["name"] == "MONGODB_URI")
    out: Dict[str, Any] = {
        "configured": "mongodb", "explicit": explicit, "origin": field["origin"] if explicit else "default",
        "editable": field["editable"], "default_uri": DEFAULT_MONGODB_URI,
        "uri": {**describe_uri(uri), "database": resolve_db_name(uri, name)},
        "driver": f"pymongo {_pkg_version('pymongo')}",
    }
    try:
        store = get_store()
        out.update(connected=True, active=store.backend, stats=store.stats(), error=None)
        from core.scheduler_store import supports_transactions
        out["transactions"] = supports_transactions(store.db)
    except StoreUnavailable as e:
        out.update(connected=False, active=None, stats=None, error=str(e))
    return out


@router.get("/api/storage", dependencies=[Depends(require_local)])
def api_storage():
    return storage_status()


@router.post("/api/storage/test", dependencies=[Depends(require_local)])
def api_storage_test(req: StorageUriRequest):
    uri = (req.uri or "").strip() or core_config.get("MONGODB_URI")
    if not uri:
        raise HTTPException(status_code=400, detail="Enter a MongoDB connection string to test.")
    try:
        uri = core_config.validate_value("MONGODB_URI", uri)
        db = (req.db or "").strip() or core_config.get("MONGODB_DB")
        if db:
            core_config.validate_value("MONGODB_DB", db)
    except SettingsError as e:
        raise HTTPException(status_code=400, detail=str(e))
    conn_fn = app_attr("check_connection", check_connection)
    return conn_fn(uri, db)


@router.put("/api/storage", dependencies=[Depends(require_local)])
def api_storage_save(req: StorageUriRequest):
    uri = (req.uri or "").strip()
    try:
        uri = core_config.validate_value("MONGODB_URI", uri)
        db = core_config.validate_value("MONGODB_DB", (req.db or "").strip())
    except SettingsError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not uri:
        raise HTTPException(status_code=400, detail="Enter a MongoDB connection string.")
    conn_fn = app_attr("check_connection", check_connection)
    result = conn_fn(uri, db or None)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["message"])
    try:
        save_keys({"MONGODB_URI": uri, "MONGODB_DB": db})
    except SettingsError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"test": result, "status": storage_status()}


@router.delete("/api/storage", dependencies=[Depends(require_local)])
def api_storage_clear():
    """Forgets the saved connection string: the app goes back to the local default server (still MongoDB)."""
    try:
        save_keys({"MONGODB_URI": "", "MONGODB_DB": ""})
    except SettingsError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return storage_status()
