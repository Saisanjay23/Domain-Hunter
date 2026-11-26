"""Asset scan, batch scan, image/logo analysis, and hash aggregator routes."""

import os
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict

from fastapi import APIRouter, HTTPException

from api.deps import app_attr
from api.schemas import (
    AggregateHashesRequest,
    BatchRequest,
    BulkImageAnalysisRequest,
    ImageAnalysisRequest,
    ScanRequest,
)
from api.services.image_inspector import (
    build_candidate_result,
    clean_url_string,
    decode_base64_upload,
    extract_hashes_from_text,
    fetch_single_candidate,
    scan_response,
)
from core.hasher import is_image_bytes
from core.query_gen import build_multi_hash_queries
from favicon_hash import scan_domain as core_scan_domain

router = APIRouter()
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MAX_BATCH_WORKERS = 4


@router.post("/api/scan")
def api_scan_single(req: ScanRequest):
    if not req.target or not req.target.strip():
        raise HTTPException(status_code=400, detail="Target domain or URL is required.")
    save_dir = os.path.join(PROJECT_ROOT, "downloaded_icons") if req.save_icons else None
    try:
        scanner = app_attr("scan_domain", core_scan_domain)
        raw_result = scanner(
            target=req.target.strip(),
            timeout=req.timeout,
            include_logos=req.include_logos,
            probe_subdomains=req.probe_subdomains,
            save_icons_dir=save_dir,
        )
        return scan_response(raw_result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/batch")
def api_scan_batch(req: BatchRequest):
    targets = list(dict.fromkeys(t.strip() for t in req.targets if t and t.strip() and not t.strip().startswith("#")))
    if not targets:
        raise HTTPException(status_code=400, detail="Target list cannot be empty.")
    scanner = app_attr("scan_domain", core_scan_domain)

    def run(t: str) -> Dict[str, Any]:
        try:
            raw = scanner(target=t, timeout=req.timeout, include_logos=req.include_logos, probe_subdomains=req.probe_subdomains)
            return scan_response(raw)
        except Exception as e:
            return {"domain": t, "error": str(e), "icons": [], "queries": {}}

    with ThreadPoolExecutor(max_workers=MAX_BATCH_WORKERS) as pool:
        results = list(pool.map(run, targets))
    return {"total_targets": len(results), "results": results}


@router.post("/api/aggregate-hashes")
def api_aggregate_hashes(req: AggregateHashesRequest):
    if not req.input_text or not req.input_text.strip():
        raise HTTPException(status_code=400, detail="Please provide hashes or query string.")
    found = extract_hashes_from_text(req.input_text)
    if not (found["mmh3"] or found["md5"] or found["sha256"]):
        raise HTTPException(status_code=400, detail="No MMH3 (signed 32-bit), MD5 or SHA256 hashes found in the input.")
    return {
        "hashes_count": len(found["mmh3"]) + len(found["md5"]) + len(found["sha256"]),
        "unique_hashes": found["mmh3"],
        "unique_md5": found["md5"],
        "unique_sha256": found["sha256"],
        "queries": found["queries"],
    }


@router.post("/api/analyze-image")
def api_analyze_image(req: ImageAnalysisRequest):
    if req.image_url:
        cand = fetch_single_candidate(req.image_url, idx=1, timeout=req.timeout, compare_phash=req.compare_phash)
        if cand.get("error"):
            raise HTTPException(status_code=400, detail=cand["error"])
        return {
            "image_url": cand.get("real_url") or req.image_url,
            "original_url": req.image_url,
            "is_unwrapped": cand.get("is_unwrapped", False),
            "source_domain": cand.get("source_domain"),
            "preview_base64": cand.get("preview_base64"),
            "analysis": cand["analysis"],
            "queries": cand["queries"],
            "similarity": cand["similarity"],
        }
    if req.image_base64:
        try:
            content = decode_base64_upload(req.image_base64)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid base64 image data: {str(e)}")
        if not is_image_bytes(content):
            raise HTTPException(status_code=400, detail="Uploaded data is not a recognised image.")
        cand = build_candidate_result("file_1", "file", "Uploaded Image", None, content, "Uploaded Base64 Image", False, req.compare_phash)
        return {
            "image_url": None,
            "original_url": "Uploaded Image",
            "is_unwrapped": False,
            "source_domain": "Uploaded Base64 Image",
            "preview_base64": cand["preview_base64"],
            "analysis": cand["analysis"],
            "queries": cand["queries"],
            "similarity": cand["similarity"],
        }
    raise HTTPException(status_code=400, detail="Please provide an image_url or image_base64 upload.")


@router.post("/api/analyze-images-bulk")
def api_analyze_images_bulk(req: BulkImageAnalysisRequest):
    expanded_urls = []
    for raw in req.image_urls:
        if not raw:
            continue
        for line in raw.splitlines():
            line_clean = line.strip()
            if not line_clean:
                continue
            parts = [line_clean] if line_clean.lower().startswith("data:") else line_clean.split(",")
            for sub in parts:
                if not sub.strip():
                    continue
                sub_clean = clean_url_string(sub)
                if sub_clean and sub_clean not in expanded_urls:
                    expanded_urls.append(sub_clean)

    with ThreadPoolExecutor(max_workers=6) as pool:
        candidates = list(pool.map(
            lambda pair: fetch_single_candidate(pair[1], idx=pair[0] + 1, timeout=req.timeout, compare_phash=req.compare_phash),
            enumerate(expanded_urls),
        ))

    for idx, b64_item in enumerate(req.images_base64):
        file_name = str(b64_item.get("name") or f"image_{idx+1}")
        try:
            content = decode_base64_upload(str(b64_item.get("data", "")))
            if not is_image_bytes(content):
                raise ValueError("not a recognised image format")
            candidates.append(build_candidate_result(
                f"file_{idx+1}", "file", file_name, None, content, f"Upload: {file_name}", False, req.compare_phash,
            ))
        except Exception as e:
            from api.services.image_inspector import error_candidate
            candidates.append(error_candidate(f"file_{idx+1}", "file", file_name, None, f"Upload: {file_name}", f"Invalid image upload: {str(e)}"))

    ok = [c["analysis"] for c in candidates if c.get("analysis")]
    unique_mmh3 = list(dict.fromkeys(a["mmh3"] for a in ok if a.get("mmh3") is not None))
    master_queries = build_multi_hash_queries(
        unique_mmh3,
        [a["md5"] for a in ok if a.get("md5")],
        [a["sha256"] for a in ok if a.get("sha256")],
    )

    def sort_key(c):
        if c.get("error"):
            return -1
        if c.get("similarity") and c["similarity"].get("similarity_percent") is not None:
            return c["similarity"]["similarity_percent"]
        return 0

    return {
        "total_submitted": len(candidates),
        "successful_count": len(ok),
        "unique_mmh3_count": len(unique_mmh3),
        "candidates": sorted(candidates, key=sort_key, reverse=True),
        "unique_mmh3": unique_mmh3,
        "master_queries": master_queries,
    }
