import base64
from importlib.metadata import PackageNotFoundError, version as _version
import os
import re
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Tuple, Dict, Any
from urllib.parse import urlparse, parse_qs, unquote, urljoin

import requests
import urllib3
from bs4 import BeautifulSoup
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from favicon_hash import scan_domain
from core.crawler import decode_data_uri, DEFAULT_USER_AGENT
from core.exporter import clean_icon_dict_for_export
from core.hasher import analyze_icon_bytes, is_image_bytes, sniff_image_format
from core.query_gen import generate_search_queries, build_multi_hash_queries
from core.matcher import calculate_similarity
from core.impersonation import generate_impersonation_recon_suite, capture_domains_from_keywords
from core.hunter import run_hunt, hunt_for_export, HuntCancelled
from core.permutations import DEPTHS
from core.store import get_store, Store, StoreError, StoreUnavailable, TRIAGE_STATUSES, default_path
from core import config as core_config
from core.mongouri import describe_uri, redact as redact_uri, resolve_db_name
from core.migrate import copy_store
from core import takedown, alerts as alerts_mod, feeds as feeds_mod
from core.domains import registrable_domain
from core.config import (sources_status, key_status, save_keys, add_key, remove_key, make_primary, get_list,
                         key_id, SettingsError, SOURCES, SOURCE_LINKS, KEY_FIELDS)
from core.keypool import POOL, SourceError as PoolError
from core.sources import check_key
import threading
import uuid

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup FastAPI App
app = FastAPI(
    title="Favicon & Threat Intel Hash Scanner API",
    description="Multi-source favicon and manifest icon crawler with MMH3, MD5, SHA256, and pHash calculation.",
    version="1.1.0",
)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "web", "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_PREVIEW_BYTES = 512 * 1024
MAX_BATCH_WORKERS = 4
MAX_LAUNCH_URLS = 40

INT32_MIN, INT32_MAX = -(2 ** 31), 2 ** 31 - 1


class ScanRequest(BaseModel):
    target: str
    include_logos: bool = True
    probe_subdomains: bool = True
    save_icons: bool = True
    timeout: int = Field(12, ge=2, le=60)


class BatchRequest(BaseModel):
    targets: List[str]
    include_logos: bool = True
    probe_subdomains: bool = True
    timeout: int = Field(10, ge=2, le=60)


class ImageAnalysisRequest(BaseModel):
    image_url: Optional[str] = None
    image_base64: Optional[str] = None
    compare_phash: Optional[str] = None
    timeout: int = Field(12, ge=2, le=60)


class BulkImageAnalysisRequest(BaseModel):
    image_urls: List[str] = []
    images_base64: List[dict] = []
    compare_phash: Optional[str] = None
    timeout: int = Field(12, ge=2, le=60)


class AggregateHashesRequest(BaseModel):
    input_text: str


class LaunchEnginesRequest(BaseModel):
    urls: List[str]


class ImpersonationDorksRequest(BaseModel):
    keywords: str
    include_variants: bool = False


class ImpersonationCaptureRequest(BaseModel):
    keywords: str
    include_variants: bool = False
    use_ct: bool = True
    use_intel: bool = True
    use_feeds: bool = True
    use_dns: bool = False


# --------------------------------------------------------------------------- helpers
def clean_url_string(raw: str) -> str:
    """Cleans up raw URL strings, repairing scheme typos and protocol-relative links."""
    s = raw.strip()
    # Strip quotes, angle brackets, semicolons, commas
    s = re.sub(r'^[<"\'`]+|[>"\'`,;]+$', '', s).strip()
    if s.lower().startswith("data:"):
        return s
    # Auto-repair typos like 'https: /' or 'https:  //'
    s = re.sub(r'^(https?):\s*/*', r'\1://', s, flags=re.I)
    # Protocol-relative
    if s.startswith("//"):
        s = "https:" + s
    # Missing scheme: e.g. avatars.mds.yandex.net/... or cdn.example.com/logo.png
    elif not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', s):
        s = "https://" + s
    return s


def is_http_url(url: str) -> bool:
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


def extract_candidate_urls(raw_url: str) -> List[str]:
    """
    Extracts direct image candidate URLs from search engines (Yandex, Google Lens/Images, Bing)
    and social/hosting platforms in priority order, falling back to the raw URL.
    """
    cleaned = clean_url_string(raw_url)
    if cleaned.startswith("data:"):
        return [cleaned]

    candidates = []
    try:
        parsed = urlparse(cleaned)
        qs = parse_qs(parsed.query)

        # Priority query param keys for wrapped search engine image views
        priority_keys = [
            "img_url", "imgurl", "image_url", "mediaurl",
            "orig_url", "original_url", "source_url", "src", "source",
            "url", "u", "thumb", "thumbnail",
        ]

        for k in priority_keys:
            for val in qs.get(k, []):
                val_cleaned = clean_url_string(unquote(val.strip()))
                if is_http_url(val_cleaned) and val_cleaned not in candidates:
                    candidates.append(val_cleaned)

        # Imgur page to direct image
        if parsed.netloc.endswith("imgur.com") and not parsed.path.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".webp")):
            parts = parsed.path.strip("/").split("/")
            if len(parts) == 1 and parts[0]:
                candidates.insert(0, f"https://i.imgur.com/{parts[0]}.png")
    except Exception:
        pass

    if cleaned not in candidates:
        candidates.append(cleaned)
    return candidates


def extract_images_from_html(html_text, base_url: str) -> List[Tuple[str, str]]:
    """
    Parses an HTML webpage (e.g. phishing site, landing page) to locate logo,
    favicon, or brand image URLs. Returns list of (image_url, source_description).
    """
    soup = BeautifulSoup(html_text, "html.parser")
    base = soup.find("base", href=True)
    if base:
        base_url = urljoin(base_url, base["href"].strip())
    found = []

    # 1. OpenGraph / Twitter meta image
    for meta in soup.find_all("meta"):
        prop = (meta.get("property") or meta.get("name") or "").lower()
        if prop in ("og:image", "og:image:url", "og:image:secure_url", "twitter:image", "twitter:image:src"):
            href = (meta.get("content") or "").strip()
            if href:
                found.append((urljoin(base_url, href), f"meta[{prop}]"))

    # 2. Favicons and Apple Touch Icons
    for link in soup.find_all("link"):
        rel = link.get("rel")
        rels = {r.lower() for r in (rel if isinstance(rel, list) else str(rel or "").split())}
        if rels & {"icon", "apple-touch-icon", "apple-touch-icon-precomposed", "mask-icon"}:
            href = (link.get("href") or "").strip()
            if href:
                found.append((href if href.startswith("data:") else urljoin(base_url, href), f"link[{' '.join(sorted(rels))}]"))

    # 3. Logo/Brand/Header Images
    for img in soup.find_all("img"):
        src = (img.get("src") or img.get("data-src") or "").strip()
        if not src:
            continue
        attrs_str = " ".join([
            str(img.get("class", "")),
            str(img.get("id", "")),
            str(img.get("alt", "")),
            src,
        ]).lower()
        if any(k in attrs_str for k in ("logo", "brand", "header-img", "site-icon")):
            found.append((src if src.startswith("data:") else urljoin(base_url, src), "img[logo]"))

    # 4. Fallback to any <img> if none found so far
    if not found:
        for img in soup.find_all("img"):
            src = (img.get("src") or img.get("data-src") or "").strip()
            if src and not src.startswith("data:"):
                found.append((urljoin(base_url, src), "img[first]"))
                break

    # 5. Last resort: the site's /favicon.ico
    root = urlparse(base_url)
    if root.scheme in ("http", "https"):
        found.append((f"{root.scheme}://{root.netloc}/favicon.ico", "fallback[/favicon.ico]"))

    # Deduplicate while preserving order
    deduped = []
    seen = set()
    for u, tag in found:
        if u not in seen:
            seen.add(u)
            deduped.append((u, tag))
    return deduped


_MIME_BY_FORMAT = {
    "PNG": "image/png", "JPEG": "image/jpeg", "MPO": "image/jpeg", "GIF": "image/gif",
    "WEBP": "image/webp", "AVIF": "image/avif", "ICO": "image/x-icon", "CUR": "image/x-icon",
    "BMP": "image/bmp", "SVG": "image/svg+xml",
}


def make_preview_data_uri(content: bytes, fmt: Optional[str] = None) -> Optional[str]:
    """
    Creates a base64 data URI so the browser never has to hotlink the suspect host
    (keeps analyst IP away from phishing infrastructure and avoids CORS/hotlink blocks).
    """
    if not content or len(content) > MAX_PREVIEW_BYTES:
        return None
    fmt = (fmt or sniff_image_format(content) or "PNG").upper()
    mime = _MIME_BY_FORMAT.get(fmt, "image/png")
    return f"data:{mime};base64,{base64.b64encode(content).decode('ascii')}"


BROWSER_IMAGE_HEADERS = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "image",
    "Sec-Fetch-Mode": "no-cors",
    "Sec-Fetch-Site": "cross-site",
}


class _Fetched:
    def __init__(self, resp: requests.Response, content: bytes):
        self.status_code = resp.status_code
        self.url = resp.url
        self.headers = resp.headers
        self.content = content
        self.encoding = resp.encoding


def http_get_limited(url: str, headers: Dict[str, str], timeout: int, max_bytes: int = MAX_IMAGE_BYTES) -> _Fetched:
    """GET with a hard size cap (stops reading after max_bytes)."""
    with requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True, stream=True) as resp:
        chunks, total = [], 0
        for chunk in resp.iter_content(65536):
            chunks.append(chunk)
            total += len(chunk)
            if total >= max_bytes:
                break
        return _Fetched(resp, b"".join(chunks)[:max_bytes])


def build_candidate_result(
    idx: str, ctype: str, original_url: str, real_url: Optional[str], content: bytes,
    source_domain: str, is_unwrapped: bool, compare_phash: Optional[str],
) -> Dict[str, Any]:
    analysis = analyze_icon_bytes(content)
    sim = calculate_similarity(compare_phash, analysis["phash"]) if compare_phash and analysis.get("phash") else None
    return {
        "id": idx,
        "type": ctype,
        "original_url": original_url,
        "real_url": real_url,
        "preview_base64": make_preview_data_uri(content, analysis.get("format")),
        "is_unwrapped": is_unwrapped,
        "source_domain": source_domain,
        "analysis": analysis,
        "queries": generate_search_queries([analysis]),
        "similarity": sim,
        "error": None,
    }


def error_candidate(idx: str, ctype: str, original_url: str, real_url: Optional[str], source_domain: str, error: str) -> Dict[str, Any]:
    return {
        "id": idx,
        "type": ctype,
        "original_url": original_url,
        "real_url": real_url,
        "preview_base64": None,
        "is_unwrapped": False,
        "source_domain": source_domain,
        "analysis": None,
        "queries": None,
        "similarity": None,
        "error": error,
    }


def fetch_single_candidate(raw_url: str, idx: int = 1, timeout: int = 15, compare_phash: Optional[str] = None) -> dict:
    """
    Robustly fetches, unwraps, and analyzes any image URL or embedded webpage asset.
    Handles anti-hotlinking, missing schemes, data URIs, HTML landing pages, and search wrappers.
    """
    cid = f"url_{idx}"
    cleaned = clean_url_string(raw_url)

    # 1. Direct Data URI
    if cleaned.lower().startswith("data:"):
        content = decode_data_uri(cleaned)
        if not content or not is_image_bytes(content):
            return error_candidate(cid, "data_uri", "data:image/...", None, "Embedded Data URI", "Invalid or non-image Data URI")
        return build_candidate_result(cid, "data_uri", "data:image/...", None, content, "Embedded Data URI", False, compare_phash)

    candidates = [c for c in extract_candidate_urls(raw_url) if is_http_url(c)]
    last_error = None
    for cand_url in candidates:
        try:
            parsed = urlparse(cand_url)
            cand_domain = parsed.netloc or "external"
            headers = dict(BROWSER_IMAGE_HEADERS)

            # Step A: standard browser request
            resp = http_get_limited(cand_url, headers, timeout)

            # Step B: Anti-hotlinking / 403 fallback: retry with Referer set to the domain itself
            if resp.status_code in (401, 403):
                headers["Referer"] = f"{parsed.scheme or 'https'}://{parsed.netloc}/"
                headers["Sec-Fetch-Site"] = "same-origin"
                resp = http_get_limited(cand_url, headers, timeout)

            # Step C: If still 403 and the URL was unwrapped from a search engine, use its Referer
            if resp.status_code in (401, 403) and cand_url != cleaned:
                orig_parsed = urlparse(cleaned)
                headers["Referer"] = f"{orig_parsed.scheme}://{orig_parsed.netloc}/"
                headers["Sec-Fetch-Site"] = "cross-site"
                resp = http_get_limited(cand_url, headers, timeout)

            if resp.status_code == 200 and resp.content:
                # Direct image
                if is_image_bytes(resp.content):
                    return build_candidate_result(
                        cid, "url", raw_url, cand_url, resp.content, cand_domain,
                        cand_url != cleaned, compare_phash,
                    )

                # HTML web page (phishing site, landing page, ...): extract its logo / favicon
                ct = resp.headers.get("content-type", "").lower()
                head = resp.content[:1024].lower()
                if "text/html" in ct or b"<html" in head or b"<!doctype" in head:
                    for img_url, source_tag in extract_images_from_html(resp.content, resp.url):
                        try:
                            if img_url.startswith("data:"):
                                sub_content = decode_data_uri(img_url)
                            else:
                                sub = http_get_limited(img_url, BROWSER_IMAGE_HEADERS, timeout)
                                sub_content = sub.content if sub.status_code == 200 else None
                            if sub_content and is_image_bytes(sub_content):
                                host = urlparse(img_url).netloc or urlparse(resp.url).netloc
                                return build_candidate_result(
                                    cid, "url", raw_url, None if img_url.startswith("data:") else img_url,
                                    sub_content, f"{host} ({source_tag})", True, compare_phash,
                                )
                        except Exception:
                            continue
                    last_error = "Web page fetched, but no logo/favicon image could be extracted"
                    continue

                last_error = f"Response is not an image (content-type: {ct or 'unknown'})"
                continue

            last_error = f"HTTP {resp.status_code}"
        except Exception as e:
            last_error = str(e)

    return error_candidate(
        cid, "url", raw_url, cleaned, urlparse(cleaned).netloc or "external",
        last_error or "Unable to extract or fetch image",
    )


def decode_base64_upload(b64_str: str) -> bytes:
    if "," in b64_str and b64_str.lstrip().lower().startswith("data:"):
        b64_str = b64_str.split(",", 1)[1]
    b64_str = re.sub(r"\s+", "", b64_str)
    return base64.b64decode(b64_str + "=" * (-len(b64_str) % 4))


def api_icon(icon: Dict[str, Any], with_preview: bool = True) -> Dict[str, Any]:
    out = clean_icon_dict_for_export(icon)
    if with_preview:
        out["preview"] = make_preview_data_uri(icon.get("_raw_bytes") or b"", icon.get("format"))
    return out


def scan_response(raw: Dict[str, Any], with_preview: bool = True) -> Dict[str, Any]:
    return {
        "domain": raw["domain"],
        "resolved_url": raw["resolved_url"],
        "reachable": raw.get("reachable", True),
        "icons": [api_icon(icon, with_preview) for icon in raw["icons"]],
        "queries": raw["queries"],
        "saved_icon_files": raw.get("saved_icon_files", []),
    }


# --------------------------------------------------------------------------- routes
# Routes are plain `def` so FastAPI runs them in its threadpool: scans are blocking
# network I/O and would otherwise freeze the whole server for every other request.

@app.get("/api/health")
def api_health():
    return {"status": "ok", "service": "CyberIntel Favicon Scanner"}


@app.post("/api/launch-engines")
def api_launch_engines(req: LaunchEnginesRequest):
    """
    Opens the given search engine URLs in the system browser (bypasses popup blockers).
    Only absolute http(s) URLs are accepted - never local paths or other schemes.
    """
    clean_urls = [u.strip() for u in (req.urls or []) if u and is_http_url(u.strip())]
    if not clean_urls:
        raise HTTPException(status_code=400, detail="No valid HTTP(S) URLs provided.")
    clean_urls = clean_urls[:MAX_LAUNCH_URLS]

    opened = 0
    use_shell = hasattr(os, "startfile")
    for u in clean_urls:
        try:
            if use_shell:
                # Native Windows ShellExecute: goes to the running browser without profile-lock errors
                os.startfile(u)
            else:
                webbrowser.open_new_tab(u)
            opened += 1
            if len(clean_urls) > 1:
                time.sleep(0.12)
        except Exception:
            continue

    return {"status": "ok" if opened else "error", "opened": opened, "mode": "shell" if use_shell else "webbrowser"}


@app.post("/api/impersonation-dorks")
def api_impersonation_dorks(req: ImpersonationDorksRequest):
    """
    Generates domain impersonation wildcards and reconnaissance dorks
    across FOFA, Censys, URLScan, Shodan, crt.sh, and search engines.
    """
    if not req.keywords or not req.keywords.strip():
        raise HTTPException(status_code=400, detail="No keywords provided.")
    try:
        return generate_impersonation_recon_suite(req.keywords, include_variants=req.include_variants)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/impersonation-dorks/capture")
def api_impersonation_capture(req: ImpersonationCaptureRequest):
    """
    Executes the generated keyword dorks live across crt.sh, URLScan,
    configured threat-intel sources, and phishing feeds to capture matching domains.
    """
    if not req.keywords or not req.keywords.strip():
        raise HTTPException(status_code=400, detail="No keywords provided.")
    try:
        return capture_domains_from_keywords(
            req.keywords,
            include_variants=req.include_variants,
            use_ct=req.use_ct,
            use_intel=req.use_intel,
            use_feeds=req.use_feeds,
            use_dns=req.use_dns,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/", response_class=FileResponse)
def serve_index():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if not os.path.isfile(index_path):
        raise HTTPException(status_code=404, detail="Web UI index.html not found")
    return FileResponse(index_path)


@app.post("/api/scan")
def api_scan_single(req: ScanRequest):
    if not req.target or not req.target.strip():
        raise HTTPException(status_code=400, detail="Target domain or URL is required.")

    save_dir = os.path.join(os.path.dirname(__file__), "downloaded_icons") if req.save_icons else None

    try:
        raw_result = scan_domain(
            target=req.target.strip(),
            timeout=req.timeout,
            include_logos=req.include_logos,
            probe_subdomains=req.probe_subdomains,
            save_icons_dir=save_dir,
        )
        return scan_response(raw_result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def extract_hashes_from_text(text: str) -> Dict[str, List]:
    """
    Pulls MMH3 / MD5 / SHA256 values out of free text or pasted queries.
    If the text contains favicon-hash query syntax (icon_hash=, http.favicon.hash:, iconhash:),
    only numbers inside those clauses are taken, so values like status_code="200" are ignored.
    """
    sha256s = re.findall(r"\b[a-fA-F0-9]{64}\b", text)
    md5s = re.findall(r"\b[a-fA-F0-9]{32}\b", text)

    mmh3_raw: List[str] = []
    clauses = re.findall(r'(?:icon_hash|favicon\.hash|iconhash|hash_shodan)\s*[:=]+\s*"?([-\d,\s"|]+)', text, re.I)
    for clause in clauses:
        mmh3_raw.extend(re.findall(r"-?\d+", clause))
    if not clauses:
        stripped = re.sub(r"\b[a-fA-F0-9]{32,64}\b", " ", text)
        mmh3_raw = re.findall(r"(?<![\w.])-?\d+(?![\w.])", stripped)

    mmh3s = []
    for h in mmh3_raw:
        v = int(h)
        if INT32_MIN <= v <= INT32_MAX:
            mmh3s.append(v)

    return {
        "mmh3": list(dict.fromkeys(mmh3s)),
        "md5": list(dict.fromkeys(m.lower() for m in md5s)),
        "sha256": list(dict.fromkeys(s.lower() for s in sha256s)),
    }


@app.post("/api/aggregate-hashes")
def api_aggregate_hashes(req: AggregateHashesRequest):
    if not req.input_text or not req.input_text.strip():
        raise HTTPException(status_code=400, detail="Please provide hashes or query string.")

    found = extract_hashes_from_text(req.input_text)
    if not (found["mmh3"] or found["md5"] or found["sha256"]):
        raise HTTPException(status_code=400, detail="No MMH3 (signed 32-bit), MD5 or SHA256 hashes found in the input.")

    queries = build_multi_hash_queries(found["mmh3"], found["md5"], found["sha256"])
    return {
        "hashes_count": len(found["mmh3"]) + len(found["md5"]) + len(found["sha256"]),
        "unique_hashes": found["mmh3"],
        "unique_md5": found["md5"],
        "unique_sha256": found["sha256"],
        "queries": queries,
    }


@app.post("/api/batch")
def api_scan_batch(req: BatchRequest):
    targets = list(dict.fromkeys(t.strip() for t in req.targets if t and t.strip() and not t.strip().startswith("#")))
    if not targets:
        raise HTTPException(status_code=400, detail="Target list cannot be empty.")

    def run(t: str) -> Dict[str, Any]:
        try:
            raw = scan_domain(
                target=t,
                timeout=req.timeout,
                include_logos=req.include_logos,
                probe_subdomains=req.probe_subdomains,
            )
            return scan_response(raw)
        except Exception as e:
            return {"domain": t, "error": str(e), "icons": [], "queries": {}}

    with ThreadPoolExecutor(max_workers=MAX_BATCH_WORKERS) as pool:
        results = list(pool.map(run, targets))

    return {
        "total_targets": len(results),
        "results": results,
    }


@app.post("/api/analyze-image")
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
    elif req.image_base64:
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
    else:
        raise HTTPException(status_code=400, detail="Please provide an image_url or image_base64 upload.")


@app.post("/api/analyze-images-bulk")
def api_analyze_images_bulk(req: BulkImageAnalysisRequest):
    """
    Accepts multiple image URLs and/or multiple uploaded base64 images.
    Extracts raw image files (unwrapping Yandex, Google Lens, Bing Images URLs,
    direct image links, data URIs, or extracting logos from candidate phishing web pages),
    computes hashes, scores visual similarity against the brand, generates individual
    search queries, and creates an aggregated master query across all candidates.
    """
    # 1. Expand and deduplicate URLs
    expanded_urls: List[str] = []
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

    # 2. Process base64 uploads
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
            candidates.append(error_candidate(f"file_{idx+1}", "file", file_name, None, f"Upload: {file_name}", f"Invalid image upload: {str(e)}"))

    # 3. Master Aggregation across all successful candidates
    ok = [c["analysis"] for c in candidates if c.get("analysis")]
    unique_mmh3 = list(dict.fromkeys(a["mmh3"] for a in ok if a.get("mmh3") is not None))
    master_queries = build_multi_hash_queries(
        unique_mmh3,
        [a["md5"] for a in ok if a.get("md5")],
        [a["sha256"] for a in ok if a.get("sha256")],
    )

    # Sort candidates: high match first, then without similarity, then errors
    def sort_key(c):
        if c.get("error"):
            return -1
        if c.get("similarity") and c["similarity"].get("similarity_percent") is not None:
            return c["similarity"]["similarity_percent"]
        return 0

    sorted_candidates = sorted(candidates, key=sort_key, reverse=True)

    return {
        "total_submitted": len(candidates),
        "successful_count": len(ok),
        "unique_mmh3_count": len(unique_mmh3),
        "candidates": sorted_candidates,
        "unique_mmh3": unique_mmh3,
        "master_queries": master_queries,
    }


# --------------------------------------------------------------------------- impersonation hunt
# Hunts take 1-5 minutes, so they run as background jobs that the UI polls.

class HuntRequest(BaseModel):
    target: str
    depth: str = "standard"
    use_ct: bool = True
    verify: bool = True
    use_rdap: bool = True
    use_intel: bool = True
    use_feeds: bool = True
    allowlist: List[str] = Field(default_factory=list)
    keywords: List[str] = Field(default_factory=list)
    timeout: int = Field(8, ge=3, le=30)
    max_verify: int = Field(400, ge=10, le=2000)


HUNT_JOBS: Dict[str, Dict[str, Any]] = {}
HUNT_LOCK = threading.Lock()
MAX_HUNT_JOBS = 20
MAX_RUNNING_HUNTS = 2


def hunt_api_result(result: Dict[str, Any]) -> Dict[str, Any]:
    out = hunt_for_export(result)
    out["brand"]["icons"] = [api_icon(i) for i in result["brand"]["icons"]]
    return out


def _run_hunt_job(job_id: str, req: HuntRequest, watch_id: Optional[int] = None) -> None:
    job = HUNT_JOBS[job_id]

    def progress(stage, pct, msg, stats):
        job.update(stage=stage, progress=pct, message=msg, stats=stats, updated=time.time())

    try:
        result = run_hunt(
            req.target.strip(), depth=req.depth, use_ct=req.use_ct, verify=req.verify, use_rdap=req.use_rdap, use_intel=req.use_intel,
            use_feeds=req.use_feeds, extra_allowlist=req.allowlist, extra_keywords=req.keywords, timeout=req.timeout,
            max_verify=req.max_verify, progress=progress, cancel=job["cancel"],
        )
        api_result = hunt_api_result(result)
        api_result["hunt_id"] = job_id
        try:
            store = get_store()
            store.decorate(api_result, exclude_id=job_id)  # triage state, first-seen, new-since-last-hunt
            store.save_hunt(job_id, api_result, scheduled=watch_id is not None)
        except Exception as e:  # history is a convenience: never lose the result because of it
            api_result.setdefault("errors", []).append(f"Could not save to history ({safe_error(e)})")
        job.update(status="done", progress=100, result=api_result, stats=api_result["stats"])
        if watch_id is not None:
            _finish_watch_safe(watch_id, job_id, api_result)
    except HuntCancelled:
        job.update(status="cancelled", message="Hunt cancelled")
        if watch_id is not None:
            _finish_watch_safe(watch_id, job_id, None, error="cancelled")
    except Exception as e:
        job.update(status="error", message=f"{e.__class__.__name__}: {e}")
        if watch_id is not None:
            _finish_watch_safe(watch_id, job_id, None, error=f"{e.__class__.__name__}: {e}")
    finally:
        job["finished"] = time.time()


def safe_error(e: BaseException) -> str:
    """Error text with any MongoDB credentials removed."""
    msg = f"{e.__class__.__name__}: {e}"
    uri = core_config.get("MONGODB_URI")
    return redact_uri(msg, uri) if uri else msg


def _finish_watch_safe(*args: Any, **kwargs: Any) -> None:
    try:
        _finish_watch(*args, **kwargs)
    except Exception:  # storage trouble must never turn a finished hunt into a failed one
        pass


def _finish_watch(watch_id: int, job_id: str, result: Optional[Dict[str, Any]], error: Optional[str] = None) -> None:
    """Records the outcome of a scheduled hunt and raises an alert (in-app and webhook) when warranted."""
    store = get_store()
    w = store.watch_get(watch_id, include_secret=True)
    if not w:
        return
    if error or result is None:
        store.watch_update(watch_id, last_run=time.time(), last_hunt=job_id, last_status=f"error: {error}")
        store.alert_add(w["brand"], "error", f"Scheduled hunt for {w['brand']} failed", error or "unknown error", job_id)
        return
    store.watch_update(watch_id, last_run=time.time(), last_hunt=job_id, last_status="ok")
    note = alerts_mod.compose(w["brand"], result, w["min_score"])
    if not note:
        return
    delivery = ""
    if note["notify"] and w.get("webhook_url"):
        ok, msg = alerts_mod.send_webhook(w["webhook_url"], note["title"], note["body"],
                                          {"brand": w["brand"], "domains": note["domains"], "hunt_id": job_id})
        delivery = ("webhook: " if ok else "webhook failed: ") + msg
    store.alert_add(w["brand"], note["level"], note["title"], note["body"], job_id, delivery)


@app.get("/api/sources")
def api_sources():
    """Which threat-intel sources are configured (never returns key values)."""
    return {"sources": sources_status()}


# --------------------------------------------------------------------------- API key settings
# These endpoints write secrets to .env, so they only answer requests made from this machine,
# addressed to a loopback host name (blocks DNS rebinding) and not sent by another website.
SETTINGS_ALLOWED_CLIENTS = {"127.0.0.1", "::1"}
SETTINGS_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}


def require_local(request: Request) -> None:
    client = request.client.host if request.client else ""
    host = (request.headers.get("host") or "").rsplit(":", 1)[0].strip("[]").lower()
    origin = request.headers.get("origin")
    origin_host = (urlparse(origin).hostname or "").lower() if origin else None
    foreign_origin = origin_host is not None and origin_host not in SETTINGS_ALLOWED_HOSTS
    if client not in SETTINGS_ALLOWED_CLIENTS or host not in SETTINGS_ALLOWED_HOSTS or foreign_origin:
        raise HTTPException(status_code=403, detail="API keys can only be managed from this machine (http://127.0.0.1 or http://localhost).")


def require_same_origin(request: Request) -> None:
    """Blocks cross-site writes (CSRF / DNS rebinding): a browser always sends Origin on cross-site requests."""
    origin = request.headers.get("origin")
    if origin and urlparse(origin).netloc.lower() != (request.headers.get("host") or "").lower():
        raise HTTPException(status_code=403, detail="Cross-site requests are not allowed.")


class SaveKeysRequest(BaseModel):
    values: Dict[str, str]


class TestKeyRequest(BaseModel):
    source: str
    values: Dict[str, str] = Field(default_factory=dict)  # a typed, unsaved key
    key_id: Optional[str] = None                          # one saved key
    all: bool = False                                     # every saved key


class KeyRefRequest(BaseModel):
    name: str
    id: str


class AddKeyRequest(BaseModel):
    name: str
    value: str


class ResetRequest(BaseModel):
    source: Optional[str] = None


def settings_payload() -> Dict[str, Any]:
    fields = key_status()
    for f in fields:
        if f.get("multi"):
            status = POOL.status(f["source"])
            for k in f["keys"]:
                k.update(status.get(k["id"], {"state": "standby", "uses": 0}))
    return {
        "fields": fields,
        "sources": [{"id": k, "name": m["name"], "does": m["does"], "key_required": m["key_required"],
                     "env": m["env"][0], "link": SOURCE_LINKS.get(k)} for k, m in SOURCES.items()],
    }


def _settings_call(fn, *args):
    try:
        fn(*args)
    except SettingsError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return settings_payload()


@app.get("/api/settings/keys", dependencies=[Depends(require_local)])
def api_get_keys():
    """Key status with masked hints only (last 4 characters). Values are never returned."""
    return settings_payload()


@app.put("/api/settings/keys", dependencies=[Depends(require_local)])
def api_save_keys(req: SaveKeysRequest):
    try:
        changed = save_keys(req.values)
    except SettingsError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"changed": changed, **settings_payload()}


@app.post("/api/settings/keys/add", dependencies=[Depends(require_local)])
def api_add_key(req: AddKeyRequest):
    """Adds one key to a source's rotation list."""
    return _settings_call(add_key, req.name, req.value)


@app.post("/api/settings/keys/remove", dependencies=[Depends(require_local)])
def api_remove_key(req: KeyRefRequest):
    payload = _settings_call(remove_key, req.name, req.id)
    POOL.reset(KEY_FIELDS[req.name]["source"], req.id)
    return payload


@app.post("/api/settings/keys/primary", dependencies=[Depends(require_local)])
def api_primary_key(req: KeyRefRequest):
    """Moves a key to the front of the rotation (tried first)."""
    return _settings_call(make_primary, req.name, req.id)


@app.post("/api/settings/keys/reset", dependencies=[Depends(require_local)])
def api_reset_keys(req: ResetRequest):
    """Clears cooldowns / invalid flags so paused keys are tried again."""
    if req.source is not None and req.source not in SOURCES:
        raise HTTPException(status_code=400, detail="Unknown source.")
    POOL.reset(req.source)
    return settings_payload()


def _test_saved(source: str, env: str, value: str) -> Dict[str, Any]:
    result = check_key(source, {env: value})
    kid = key_id(value)
    POOL.reset(source, kid)  # a fresh test replaces whatever state the key had
    if not result["ok"] and result.get("kind") in ("auth", "quota", "rate_limit", "forbidden"):
        POOL.mark_failure(source, value, PoolError(result["message"], kind=result["kind"]))
    return {"id": kid, **{k: v for k, v in result.items() if k != "kind"}}


@app.post("/api/settings/keys/test", dependencies=[Depends(require_local)])
def api_test_key(req: TestKeyRequest):
    if req.source not in SOURCES:
        raise HTTPException(status_code=400, detail="Unknown source.")
    env = SOURCES[req.source]["env"][0]
    saved = get_list(env)
    if req.all:
        results = []
        for i, v in enumerate(saved):
            if i and req.source == "shodan":
                time.sleep(1.1)  # Shodan allows about one API call per second
            results.append(_test_saved(req.source, env, v))
        if not results:
            only = check_key(req.source, {})
            return {"ok": only["ok"], "message": only["message"], "results": []}
        good = sum(1 for r in results if r["ok"])
        return {"ok": good > 0, "message": f"{good} of {len(results)} keys working", "results": results}
    if req.key_id:
        value = next((v for v in saved if key_id(v) == req.key_id), None)
        if value is None:
            raise HTTPException(status_code=404, detail="Key not found.")
        return _test_saved(req.source, env, value)
    result = check_key(req.source, {k: v for k, v in req.values.items() if v})
    return {k: v for k, v in result.items() if k != "kind"}


def start_hunt(req: HuntRequest, watch_id: Optional[int] = None) -> str:
    """Validates and starts a background hunt. Raises HTTPException when the request is invalid or the server is busy."""
    if not req.target or not req.target.strip():
        raise HTTPException(status_code=400, detail="Target domain is required.")
    if req.depth not in DEPTHS:
        raise HTTPException(status_code=400, detail=f"depth must be one of {', '.join(DEPTHS)}")
    with HUNT_LOCK:
        running = [j for j in HUNT_JOBS.values() if j["status"] == "running"]
        if len(running) >= MAX_RUNNING_HUNTS:
            raise HTTPException(status_code=429, detail="Two hunts are already running. Wait for one to finish or cancel it.")
        finished = sorted((j for j in HUNT_JOBS.values() if j["status"] != "running"), key=lambda j: j["created"])
        while len(HUNT_JOBS) >= MAX_HUNT_JOBS and finished:
            HUNT_JOBS.pop(finished.pop(0)["id"], None)
        job_id = uuid.uuid4().hex[:12]
        HUNT_JOBS[job_id] = {"id": job_id, "target": req.target.strip(), "status": "running", "stage": "queued",
                             "progress": 0, "message": "Starting hunt...", "stats": {}, "result": None,
                             "created": time.time(), "updated": time.time(), "cancel": threading.Event(),
                             "scheduled": watch_id is not None}
    threading.Thread(target=_run_hunt_job, args=(job_id, req, watch_id), daemon=True).start()
    return job_id


@app.post("/api/hunt", dependencies=[Depends(require_same_origin)])
def api_hunt_start(req: HuntRequest):
    return {"job_id": start_hunt(req)}


@app.get("/api/hunt/{job_id}")
def api_hunt_status(job_id: str):
    job = HUNT_JOBS.get(job_id)
    if not job:
        # After a restart the hunt may still be in the history database.
        stored = get_store().get_hunt(job_id)
        if stored:
            get_store().decorate(stored, compute_new=False)
            return {"id": job_id, "target": stored["target"], "status": "done", "progress": 100, "stage": "done",
                    "message": "Loaded from history", "stats": stored.get("stats", {}), "result": stored}
        raise HTTPException(status_code=404, detail="Unknown hunt job.")
    out = {k: v for k, v in job.items() if k not in ("cancel", "result")}
    if job["status"] == "done":
        out["result"] = job["result"]
    return out


@app.delete("/api/hunt/{job_id}", dependencies=[Depends(require_same_origin)])
def api_hunt_cancel(job_id: str):
    job = HUNT_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Unknown hunt job.")
    job["cancel"].set()
    return {"status": "cancelling"}


# --------------------------------------------------------------------------- history, triage, takedown
def _hunt_or_404(hunt_id: str) -> Dict[str, Any]:
    stored = get_store().get_hunt(hunt_id)
    if not stored:
        raise HTTPException(status_code=404, detail="Hunt not found in history.")
    get_store().decorate(stored, compute_new=False)  # fresh triage state
    return stored


def _candidate_or_404(stored: Dict[str, Any], domain: str) -> Dict[str, Any]:
    cand = next((c for c in stored.get("candidates", []) if c["domain"] == domain), None)
    if not cand:
        raise HTTPException(status_code=404, detail="Domain not found in this hunt.")
    return cand


@app.get("/api/hunts")
def api_list_hunts(target: Optional[str] = None):
    return {"hunts": get_store().list_hunts(target=target)}


@app.get("/api/hunts/{hunt_id}")
def api_get_hunt(hunt_id: str):
    return _hunt_or_404(hunt_id)


@app.delete("/api/hunts/{hunt_id}", dependencies=[Depends(require_same_origin)])
def api_delete_hunt(hunt_id: str):
    if not get_store().delete_hunt(hunt_id):
        raise HTTPException(status_code=404, detail="Hunt not found in history.")
    HUNT_JOBS.pop(hunt_id, None)
    return {"status": "deleted"}


class TriageRequest(BaseModel):
    brand: str
    domain: str
    status: str
    note: str = ""


@app.put("/api/triage", dependencies=[Depends(require_same_origin)])
def api_triage(req: TriageRequest):
    try:
        return get_store().triage_set(req.brand.strip().lower(), req.domain.strip().lower(), req.status, req.note)
    except StoreError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/hunts/{hunt_id}/takedown")
def api_takedown(hunt_id: str, domain: str):
    stored = _hunt_or_404(hunt_id)
    cand = _candidate_or_404(stored, domain)
    contacts = takedown.abuse_contacts(cand)
    return {"domain": domain, "contacts": contacts, "email": takedown.email_draft(cand, stored["target"], contacts)}


@app.get("/api/hunts/{hunt_id}/report", response_class=HTMLResponse)
def api_evidence_report(hunt_id: str, domain: str):
    stored = _hunt_or_404(hunt_id)
    cand = _candidate_or_404(stored, domain)
    return HTMLResponse(takedown.evidence_html(cand, stored["target"], takedown.abuse_contacts(cand)))


@app.get("/api/hunts/{hunt_id}/ioc")
def api_ioc_export(hunt_id: str, format: str = "txt", min_score: int = 45, status: str = ""):
    stored = _hunt_or_404(hunt_id)
    wanted = [x for x in status.split(",") if x in TRIAGE_STATUSES] or None
    picked = takedown.select_iocs(stored.get("candidates", []), min_score=min_score, statuses=wanted)
    brand = stored["target"]
    if format == "stix":
        import json as _json
        body, media, ext = _json.dumps(takedown.stix_bundle(brand, picked), indent=2), "application/json", "stix.json"
    elif format == "txt":
        body, media, ext = takedown.ioc_txt(brand, picked), "text/plain; charset=utf-8", "txt"
    else:
        raise HTTPException(status_code=400, detail="format must be txt or stix")
    return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="iocs_{brand}.{ext}"',
                                                     "X-IOC-Count": str(len(picked))})


@app.get("/api/feeds")
def api_feeds():
    return {"feeds": feeds_mod.feeds_status()}


# --------------------------------------------------------------------------- watchlist, alerts, scheduler
class WatchRequest(BaseModel):
    brand: str
    depth: str = "standard"
    interval_hours: int = Field(24, ge=1, le=24 * 30)
    min_score: int = Field(45, ge=0, le=100)
    webhook_url: str = ""
    allowlist: List[str] = Field(default_factory=list)


class WatchPatch(BaseModel):
    enabled: Optional[bool] = None
    depth: Optional[str] = None
    interval_hours: Optional[int] = Field(None, ge=1, le=24 * 30)
    min_score: Optional[int] = Field(None, ge=0, le=100)
    webhook_url: Optional[str] = None  # None keeps the saved URL, "" removes it


def _watch_payload() -> Dict[str, Any]:
    store = get_store()
    return {"watchlist": store.watch_list(), "alerts": store.alert_list(), "unread": store.alert_unread(),
            "scheduler": SCHEDULER_STATE["running"]}


def _start_watch_hunt(w: Dict[str, Any]) -> str:
    req = HuntRequest(target=w["brand"], depth=w["depth"], allowlist=w.get("allowlist") or [])
    job_id = start_hunt(req, watch_id=w["id"])
    get_store().watch_update(w["id"], last_run=time.time(), last_hunt=job_id, last_status="running")
    return job_id


@app.get("/api/watchlist")
def api_watchlist():
    return _watch_payload()


@app.post("/api/watchlist", dependencies=[Depends(require_same_origin)])
def api_watch_add(req: WatchRequest):
    brand = registrable_domain(req.brand.strip().lower().replace("https://", "").replace("http://", "").split("/")[0])
    if not brand:
        raise HTTPException(status_code=400, detail="Enter a brand domain such as paypal.com")
    if req.depth not in DEPTHS:
        raise HTTPException(status_code=400, detail=f"depth must be one of {', '.join(DEPTHS)}")
    store = get_store()
    try:
        wid = store.watch_add(brand, req.depth, req.interval_hours, req.min_score, req.webhook_url,
                              [a.strip().lower() for a in req.allowlist if a.strip()])
    except StoreError as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        _start_watch_hunt(store.watch_get(wid))  # first hunt = baseline, starts right away
    except HTTPException:
        pass  # server busy: the scheduler will pick it up
    return _watch_payload()


@app.patch("/api/watchlist/{wid}", dependencies=[Depends(require_same_origin)])
def api_watch_patch(wid: int, req: WatchPatch):
    store = get_store()
    if not store.watch_get(wid):
        raise HTTPException(status_code=404, detail="Not on the watchlist.")
    fields = {k: v for k, v in req.model_dump().items() if v is not None}
    if "depth" in fields and fields["depth"] not in DEPTHS:
        raise HTTPException(status_code=400, detail=f"depth must be one of {', '.join(DEPTHS)}")
    try:
        store.watch_update(wid, **fields)
    except StoreError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _watch_payload()


@app.delete("/api/watchlist/{wid}", dependencies=[Depends(require_same_origin)])
def api_watch_delete(wid: int):
    if not get_store().watch_delete(wid):
        raise HTTPException(status_code=404, detail="Not on the watchlist.")
    return _watch_payload()


@app.post("/api/watchlist/{wid}/run", dependencies=[Depends(require_same_origin)])
def api_watch_run(wid: int):
    w = get_store().watch_get(wid)
    if not w:
        raise HTTPException(status_code=404, detail="Not on the watchlist.")
    return {"job_id": _start_watch_hunt(w)}


@app.post("/api/watchlist/{wid}/test-webhook", dependencies=[Depends(require_same_origin)])
def api_watch_test_webhook(wid: int):
    w = get_store().watch_get(wid, include_secret=True)
    if not w:
        raise HTTPException(status_code=404, detail="Not on the watchlist.")
    if not w.get("webhook_url"):
        return {"ok": False, "message": "No webhook is set for this brand"}
    ok, msg = alerts_mod.send_webhook(w["webhook_url"], f"Test alert for {w['brand']}", "Brand Impersonation Hunter can reach this webhook.",
                                      {"brand": w["brand"], "test": True})
    return {"ok": ok, "message": msg}


class ReadRequest(BaseModel):
    id: Optional[int] = None


@app.get("/api/alerts")
def api_alerts():
    store = get_store()
    return {"alerts": store.alert_list(), "unread": store.alert_unread()}


@app.post("/api/alerts/read", dependencies=[Depends(require_same_origin)])
def api_alerts_read(req: ReadRequest):
    get_store().alert_mark_read(req.id)
    return {"unread": get_store().alert_unread()}


SCHEDULER_STATE: Dict[str, Any] = {"running": False}
SCHEDULER_TICK_SECONDS = 30


def scheduler_tick(now: Optional[float] = None) -> List[str]:
    """
    Starts a hunt for every enabled watch that is due. Returns the brands started.
    Each due hunt is claimed atomically in the store first, so when several app instances share one
    MongoDB exactly one of them runs it.
    """
    now = now or time.time()
    store = get_store()
    started: List[str] = []
    for w in store.watch_list():
        if not w["enabled"]:
            continue
        due_before = now - w["interval_hours"] * 3600
        if w["last_run"] is not None and w["last_run"] > due_before:
            continue
        previous = (w["last_run"], w.get("last_status"))
        if not store.watch_claim(w["id"], due_before, now):
            continue  # another instance claimed it
        try:
            _start_watch_hunt(w)
            started.append(w["brand"])
        except Exception:
            store.watch_update(w["id"], last_run=previous[0], last_status=previous[1])  # server busy: retry next tick
            break
    return started


def _scheduler_loop() -> None:
    while True:
        try:
            scheduler_tick()
        except Exception:  # never let the scheduler thread die
            pass
        time.sleep(SCHEDULER_TICK_SECONDS)


def _start_scheduler() -> None:
    if SCHEDULER_STATE["running"] or os.environ.get("BRAND_HUNTER_SCHEDULER", "1") == "0":
        return
    SCHEDULER_STATE["running"] = True
    threading.Thread(target=_scheduler_loop, name="watchlist-scheduler", daemon=True).start()


app.router.add_event_handler("startup", _start_scheduler)


# --------------------------------------------------------------------------- storage backend (SQLite / MongoDB)
@app.exception_handler(StoreUnavailable)
async def _handle_store_unavailable(request: Request, exc: StoreUnavailable):
    return JSONResponse(status_code=503, content={"detail": str(exc)})


def check_connection(uri: str, db_name: Optional[str] = None) -> Dict[str, Any]:
    """Tests a MongoDB connection (the driver is imported only now, not at startup)."""
    from core.mongostore import check_connection as _check
    return _check(uri, db_name)


class StorageUriRequest(BaseModel):
    uri: Optional[str] = None
    db: Optional[str] = None


class MigrateRequest(BaseModel):
    direction: str = "to_mongodb"


def _pkg_version(name: str) -> str:
    try:
        return _version(name)
    except PackageNotFoundError:
        return "not installed"


def storage_status() -> Dict[str, Any]:
    uri = core_config.get("MONGODB_URI")
    name = core_config.get("MONGODB_DB")
    field = next(f for f in key_status() if f["name"] == "MONGODB_URI")
    out: Dict[str, Any] = {
        "configured": "mongodb" if uri else "sqlite", "origin": field["origin"], "editable": field["editable"],
        "uri": ({**describe_uri(uri), "database": resolve_db_name(uri, name)} if uri else None),
        "driver": f"pymongo {_pkg_version('pymongo')}", "sqlite": {"path": default_path(), "exists": os.path.exists(default_path())},
    }
    try:
        store = get_store()
        out.update(connected=True, active=store.backend, stats=store.stats(), error=None)
    except StoreUnavailable as e:
        out.update(connected=False, active=None, stats=None, error=str(e))
    if out["sqlite"]["exists"]:
        try:
            local = Store(default_path())
            out["sqlite"].update({k: v for k, v in local.stats().items() if k != "location"})
            local.close()
        except Exception:
            pass
    return out


@app.get("/api/storage", dependencies=[Depends(require_local)])
def api_storage():
    """Which backend is active, connection details without credentials, and record counts."""
    return storage_status()


@app.post("/api/storage/test", dependencies=[Depends(require_local)])
def api_storage_test(req: StorageUriRequest):
    """Tests a typed connection string, or the saved one when none is given. Writes and removes one temporary document."""
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
    return check_connection(uri, db)


@app.put("/api/storage", dependencies=[Depends(require_local)])
def api_storage_save(req: StorageUriRequest):
    """Switches storage to MongoDB. The connection is tested first: a broken connection string is never saved."""
    uri = (req.uri or "").strip()
    try:
        uri = core_config.validate_value("MONGODB_URI", uri)
        db = core_config.validate_value("MONGODB_DB", (req.db or "").strip())
    except SettingsError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not uri:
        raise HTTPException(status_code=400, detail="Enter a MongoDB connection string.")
    result = check_connection(uri, db or None)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["message"])
    try:
        save_keys({"MONGODB_URI": uri, "MONGODB_DB": db})
    except SettingsError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"test": result, "status": storage_status()}


@app.delete("/api/storage", dependencies=[Depends(require_local)])
def api_storage_clear():
    """Back to the local SQLite file. Nothing is deleted from MongoDB."""
    try:
        save_keys({"MONGODB_URI": "", "MONGODB_DB": ""})
    except SettingsError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return storage_status()


@app.post("/api/storage/migrate", dependencies=[Depends(require_local)])
def api_storage_migrate(req: MigrateRequest):
    """Copies history, triage, watchlist and alerts between the local SQLite file and MongoDB (safe to repeat)."""
    active = get_store()
    if req.direction not in ("to_mongodb", "to_sqlite"):
        raise HTTPException(status_code=400, detail="direction must be to_mongodb or to_sqlite")
    if active.backend != "mongodb":
        raise HTTPException(status_code=400, detail="MongoDB is not the active storage yet. Save a connection string first.")
    path = default_path()
    if req.direction == "to_mongodb" and not os.path.exists(path):
        raise HTTPException(status_code=400, detail="There is no local SQLite history to copy.")
    local = Store(path)
    try:
        counts = copy_store(local, active) if req.direction == "to_mongodb" else copy_store(active, local)
    finally:
        local.close()
    return {"direction": req.direction, "copied": counts, "status": storage_status()}


def start_server(host: str = "127.0.0.1", port: int = 8080):
    import argparse
    parser = argparse.ArgumentParser(description="Favicon Scanner Web UI")
    parser.add_argument("--port", type=int, default=port, help="Port to listen on (default: 8080)")
    parser.add_argument("--host", type=str, default=host, help="Host to listen on (default: 127.0.0.1)")
    args, _ = parser.parse_known_args()

    print("\n=======================================================")
    print("[*] Starting CyberIntel Favicon Scanner Web UI...")
    print(f"[*] Dashboard URL: http://{args.host}:{args.port}")
    print("=======================================================\n")
    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    start_server()
