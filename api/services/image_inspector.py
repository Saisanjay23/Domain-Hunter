"""Image unwrapping, logo extraction, hash parsing, and scan response serialization."""

import base64
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from core.crawler import DEFAULT_USER_AGENT, decode_data_uri
from core.exporter import clean_icon_dict_for_export
from core.hasher import analyze_icon_bytes, is_image_bytes, make_preview_data_uri
from core.matcher import calculate_similarity
from core.query_gen import build_multi_hash_queries, generate_search_queries

MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_PREVIEW_BYTES = 512 * 1024
INT32_MIN, INT32_MAX = -(2 ** 31), 2 ** 31 - 1

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


def clean_url_string(raw: str) -> str:
    """Cleans up raw URL strings, repairing scheme typos and protocol-relative links."""
    s = raw.strip()
    s = re.sub(r'^[<"\'`]+|[>"\'`,;]+$', "", s).strip()
    if s.lower().startswith("data:"):
        return s
    s = re.sub(r"^(https?):\s*/*", r"\1://", s, flags=re.I)
    if s.startswith("//"):
        s = "https:" + s
    elif not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", s):
        s = "https://" + s
    return s


def is_http_url(url: str) -> bool:
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


def extract_candidate_urls(raw_url: str) -> List[str]:
    """Unwraps Google Lens, Yandex, Bing, and Imgur wrapper links to direct image candidates."""
    cleaned = clean_url_string(raw_url)
    if cleaned.startswith("data:"):
        return [cleaned]

    candidates: List[str] = []
    try:
        parsed = urlparse(cleaned)
        qs = parse_qs(parsed.query)
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
    """Extracts OpenGraph, favicon, and logo image URLs from an HTML landing page."""
    soup = BeautifulSoup(html_text, "html.parser")
    base = soup.find("base", href=True)
    if base:
        base_url = urljoin(base_url, base["href"].strip())
    found: List[Tuple[str, str]] = []

    for meta in soup.find_all("meta"):
        prop = (meta.get("property") or meta.get("name") or "").lower()
        if prop in ("og:image", "og:image:url", "og:image:secure_url", "twitter:image", "twitter:image:src"):
            href = (meta.get("content") or "").strip()
            if href:
                found.append((urljoin(base_url, href), f"meta[{prop}]"))

    for link in soup.find_all("link"):
        rel = link.get("rel")
        rels = {r.lower() for r in (rel if isinstance(rel, list) else str(rel or "").split())}
        if rels & {"icon", "apple-touch-icon", "apple-touch-icon-precomposed", "mask-icon"}:
            href = (link.get("href") or "").strip()
            if href:
                found.append((href if href.startswith("data:") else urljoin(base_url, href), f"link[{' '.join(sorted(rels))}]"))

    for img in soup.find_all("img"):
        src = (img.get("src") or img.get("data-src") or "").strip()
        if not src:
            continue
        attrs_str = " ".join([str(img.get("class", "")), str(img.get("id", "")), str(img.get("alt", "")), src]).lower()
        if any(k in attrs_str for k in ("logo", "brand", "header-img", "site-icon")):
            found.append((src if src.startswith("data:") else urljoin(base_url, src), "img[logo]"))

    if not found:
        for img in soup.find_all("img"):
            src = (img.get("src") or img.get("data-src") or "").strip()
            if src and not src.startswith("data:"):
                found.append((urljoin(base_url, src), "img[first]"))
                break

    root = urlparse(base_url)
    if root.scheme in ("http", "https"):
        found.append((f"{root.scheme}://{root.netloc}/favicon.ico", "fallback[/favicon.ico]"))

    deduped, seen = [], set()
    for u, tag in found:
        if u not in seen:
            seen.add(u)
            deduped.append((u, tag))
    return deduped


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
        "preview_base64": make_preview_data_uri(content, analysis.get("format"), MAX_PREVIEW_BYTES),
        "is_unwrapped": is_unwrapped,
        "source_domain": source_domain,
        "analysis": analysis,
        "queries": generate_search_queries([analysis]),
        "similarity": sim,
        "error": None,
    }


def error_candidate(idx: str, ctype: str, original_url: str, real_url: Optional[str], source_domain: str, error: str) -> Dict[str, Any]:
    return {
        "id": idx, "type": ctype, "original_url": original_url, "real_url": real_url,
        "preview_base64": None, "is_unwrapped": False, "source_domain": source_domain,
        "analysis": None, "queries": None, "similarity": None, "error": error,
    }


def fetch_single_candidate(raw_url: str, idx: int = 1, timeout: int = 15, compare_phash: Optional[str] = None) -> dict:
    """Fetches, unwraps, and analyzes an image URL or embedded webpage asset."""
    cid = f"url_{idx}"
    cleaned = clean_url_string(raw_url)
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
            resp = http_get_limited(cand_url, headers, timeout)

            if resp.status_code in (401, 403):
                headers["Referer"] = f"{parsed.scheme or 'https'}://{parsed.netloc}/"
                headers["Sec-Fetch-Site"] = "same-origin"
                resp = http_get_limited(cand_url, headers, timeout)

            if resp.status_code in (401, 403) and cand_url != cleaned:
                orig_parsed = urlparse(cleaned)
                headers["Referer"] = f"{orig_parsed.scheme}://{orig_parsed.netloc}/"
                headers["Sec-Fetch-Site"] = "cross-site"
                resp = http_get_limited(cand_url, headers, timeout)

            if resp.status_code == 200 and resp.content:
                if is_image_bytes(resp.content):
                    return build_candidate_result(cid, "url", raw_url, cand_url, resp.content, cand_domain, cand_url != cleaned, compare_phash)
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

    return error_candidate(cid, "url", raw_url, cleaned, urlparse(cleaned).netloc or "external", last_error or "Unable to extract or fetch image")


def decode_base64_upload(b64_str: str) -> bytes:
    if "," in b64_str and b64_str.lstrip().lower().startswith("data:"):
        b64_str = b64_str.split(",", 1)[1]
    b64_str = re.sub(r"\s+", "", b64_str)
    return base64.b64decode(b64_str + "=" * (-len(b64_str) % 4))


def api_icon(icon: Dict[str, Any], with_preview: bool = True) -> Dict[str, Any]:
    out = clean_icon_dict_for_export(icon)
    if with_preview:
        out["preview"] = make_preview_data_uri(icon.get("_raw_bytes") or b"", icon.get("format"), MAX_PREVIEW_BYTES)
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


def extract_hashes_from_text(text: str) -> Dict[str, List]:
    """Pulls MMH3 / MD5 / SHA256 values out of free text or pasted queries."""
    sha256s = re.findall(r"\b[a-fA-F0-9]{64}\b", text)
    md5s = re.findall(r"\b[a-fA-F0-9]{32}\b", text)

    mmh3_raw: List[str] = []
    clauses = re.findall(r'(?:icon_hash|favicon\.hash|iconhash|hash_shodan)\s*[:=]+\s*"?([-\d,\s"|]+)', text, re.I)
    for clause in clauses:
        mmh3_raw.extend(re.findall(r"-?\d+", clause))
    if not clauses:
        stripped = re.sub(r"\b[a-fA-F0-9]{32,64}\b", " ", text)
        mmh3_raw = re.findall(r"(?<![\w.])-?\d+(?![\w.])", stripped)

    mmh3s = [int(h) for h in mmh3_raw if INT32_MIN <= int(h) <= INT32_MAX]
    return {
        "mmh3": list(dict.fromkeys(mmh3s)),
        "md5": list(dict.fromkeys(m.lower() for m in md5s)),
        "sha256": list(dict.fromkeys(s.lower() for s in sha256s)),
        "queries": build_multi_hash_queries(list(dict.fromkeys(mmh3s)), list(dict.fromkeys(m.lower() for m in md5s)), list(dict.fromkeys(s.lower() for s in sha256s))),
    }
