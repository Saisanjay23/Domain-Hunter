"""
Bulk input for the Scan Scheduler: turn pasted text or an uploaded TXT / CSV / Excel file into monitored-domain
entries, without ever silently dropping a line.

Every input line becomes one entry:

    {"line": 3, "input": "https://www.PayPal.com/login", "domain": "paypal.com", "organization": "PayPal",
     "keywords": ["paypal", "venmo"], "status": "valid" | "invalid" | "duplicate", "error": "..."}

Accepted line formats (TXT / pasted text):
    paypal.com
    https://www.paypal.com/signin            (URL -> hostname)
    paypal.com, paypal; venmo                (domain, keywords separated by ; or |)
    paypal.com, paypal; venmo, PayPal Inc    (domain, keywords, organization)
CSV / Excel: a header row naming the columns domain (or url / host / website), keywords and organization is
used when present; otherwise the first three columns are read in that order.
"""

import base64
import csv
import io
import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

from .domains import normalize_host, split_host

MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_ENTRIES = 2000
MAX_KEYWORDS = 30
MAX_KEYWORD_LEN = 64
MAX_ORG_LEN = 120
INTERNAL_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".corp", ".intranet", ".test", ".invalid", ".example")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_KEYWORD_OK = re.compile(r"^[\w .&+'-]+$", re.UNICODE)
DOMAIN_HEADERS = ("domain", "domains", "url", "urls", "host", "hostname", "website", "original domain", "original_domain")
KEYWORD_HEADERS = ("keywords", "keyword", "brand keywords", "brand_keywords", "terms")
ORG_HEADERS = ("organization", "organisation", "org", "company", "brand", "organization name")


class InputError(ValueError):
    """The upload itself is unusable (too large, unknown type, unreadable)."""


def normalize_domain(raw: str) -> Tuple[Optional[str], Optional[str]]:
    """(domain, None) or (None, reason). URLs become their hostname; www. is dropped; IDNs are punycoded."""
    text = (raw or "").strip().strip("\"'").strip()
    if not text:
        return None, "empty"
    if len(text) > 2048:
        return None, "too long"
    if " " in text.strip():
        return None, "contains spaces"
    candidate = text
    if "://" not in candidate and "/" in candidate:
        candidate = "http://" + candidate          # bare "host/path"
    host = normalize_host(candidate)
    if not host:
        return None, "no hostname"
    if host.startswith("["):
        return None, "IP addresses cannot be monitored"
    try:
        ipaddress.ip_address(host)
        return None, "IP addresses cannot be monitored"
    except ValueError:
        pass
    if host.startswith("www."):
        host = host[4:]
    if host.startswith("*."):
        host = host[2:]
    if len(host) > 253 or "." not in host:
        return None, "not a fully qualified domain"
    if any(not _LABEL.match(label) for label in host.split(".")):
        return None, "invalid characters in the hostname"
    if host.endswith(INTERNAL_SUFFIXES) or host in ("localhost",):
        return None, "internal / reserved names cannot be monitored"
    _, label, suffix = split_host(host)
    if not label or not suffix:
        return None, "unknown public suffix (TLD)"
    return host, None


def clean_keywords(values: Any) -> Tuple[List[str], List[str]]:
    """(keywords, problems). Accepts a list or a ';' / '|' / ',' separated string. Lowercased, de-duplicated."""
    if isinstance(values, str):
        values = re.split(r"[;|,\n]", values)
    out: List[str] = []
    problems: List[str] = []
    for v in values or []:
        k = str(v or "").strip().lower()
        if not k:
            continue
        if len(k) > MAX_KEYWORD_LEN or not _KEYWORD_OK.match(k):
            problems.append(f"keyword '{k[:30]}' ignored (letters, digits, space . & + ' - only, max {MAX_KEYWORD_LEN})")
            continue
        if k not in out:
            out.append(k)
    if len(out) > MAX_KEYWORDS:
        problems.append(f"only the first {MAX_KEYWORDS} keywords are kept")
        out = out[:MAX_KEYWORDS]
    return out, problems


def clean_org(value: Any) -> str:
    text = re.sub(r"[\x00-\x1f<>]", "", str(value or "")).strip()
    return text[:MAX_ORG_LEN]


def _entry(line: int, raw_domain: str, keywords: Any = "", org: Any = "", original: Optional[str] = None) -> Dict[str, Any]:
    domain, err = normalize_domain(raw_domain)
    kws, problems = clean_keywords(keywords)
    e: Dict[str, Any] = {"line": line, "input": (original if original is not None else raw_domain)[:300], "domain": domain,
                         "organization": clean_org(org), "keywords": kws, "status": "valid" if domain else "invalid",
                         "error": err, "warnings": problems}
    return e


def _split_line(line: str) -> List[str]:
    if "\t" in line:
        return [p.strip() for p in line.split("\t")]
    return [p.strip() for p in line.split(",", 2)] if "," in line else [line.strip()]


def parse_text(text: str) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for i, raw in enumerate((text or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = _split_line(line)
        entries.append(_entry(i, parts[0], parts[1] if len(parts) > 1 else "", parts[2] if len(parts) > 2 else "", original=line))
        if len(entries) > MAX_ENTRIES:
            raise InputError(f"Too many lines (max {MAX_ENTRIES} per import)")
    return entries


def _rows_to_entries(rows: List[List[Any]]) -> List[Dict[str, Any]]:
    rows = [[("" if c is None else str(c)).strip() for c in r] for r in rows]
    rows = [r for r in rows if any(r)]
    if not rows:
        return []
    header = [c.lower() for c in rows[0]]
    cols = {"domain": 0, "keywords": 1, "organization": 2}
    start = 0
    if any(h in DOMAIN_HEADERS for h in header):
        start = 1
        cols = {"domain": next(i for i, h in enumerate(header) if h in DOMAIN_HEADERS),
                "keywords": next((i for i, h in enumerate(header) if h in KEYWORD_HEADERS), None),
                "organization": next((i for i, h in enumerate(header) if h in ORG_HEADERS), None)}
    entries = []
    for n, r in enumerate(rows[start:], start + 1):
        def col(name: str) -> str:
            i = cols.get(name)
            return r[i] if i is not None and i < len(r) else ""
        entries.append(_entry(n, col("domain"), col("keywords"), col("organization"), original=", ".join(c for c in r if c)))
        if len(entries) > MAX_ENTRIES:
            raise InputError(f"Too many rows (max {MAX_ENTRIES} per import)")
    return entries


def parse_upload(filename: str, content_b64: str) -> List[Dict[str, Any]]:
    """TXT / CSV / XLSX given as base64 (the browser reads the file; no multipart parser needed)."""
    name = (filename or "").lower().strip()
    try:
        data = base64.b64decode(content_b64 or "", validate=True)
    except Exception:
        raise InputError("The file could not be decoded")
    if len(data) > MAX_UPLOAD_BYTES:
        raise InputError(f"The file is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
    if name.endswith((".txt", ".list")):
        return parse_text(_decode_text(data))
    if name.endswith((".csv", ".tsv")):
        text = _decode_text(data)
        dialect = csv.excel_tab if name.endswith(".tsv") or ("\t" in text and "," not in text) else csv.excel
        return _rows_to_entries(list(csv.reader(io.StringIO(text), dialect)))
    if name.endswith(".xlsx"):
        if not data.startswith(b"PK"):
            raise InputError("Not a valid .xlsx file")
        try:
            import openpyxl
            wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
            try:
                ws = wb.worksheets[0]
                rows = []
                for r in ws.iter_rows(values_only=True):
                    rows.append(list(r)[:10])
                    if len(rows) > MAX_ENTRIES + 1:
                        break
            finally:
                wb.close()
        except InputError:
            raise
        except Exception as e:
            raise InputError(f"The spreadsheet could not be read ({e.__class__.__name__})")
        return _rows_to_entries(rows)
    raise InputError("Upload a .txt, .csv or .xlsx file")


def _decode_text(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-16", "latin-1"):
        try:
            text = data.decode(enc)
            if "\x00" not in text:
                return text
        except UnicodeDecodeError:
            continue
    raise InputError("The file is not text")


def mark_duplicates(entries: List[Dict[str, Any]], existing: Optional[set] = None) -> Dict[str, Any]:
    """Flags repeated domains (first occurrence wins; keywords of repeats are merged into it). Returns a summary."""
    first: Dict[str, Dict[str, Any]] = {}
    existing = existing or set()
    for e in entries:
        if e["status"] != "valid":
            continue
        d = e["domain"]
        if d in first:
            e["status"], e["error"] = "duplicate", f"same domain as line {first[d]['line']}"
            for k in e["keywords"]:
                if k not in first[d]["keywords"] and len(first[d]["keywords"]) < MAX_KEYWORDS:
                    first[d]["keywords"].append(k)
            continue
        first[d] = e
        e["already_in_batch"] = d in existing
    return {"total": len(entries), "valid": sum(e["status"] == "valid" for e in entries),
            "invalid": sum(e["status"] == "invalid" for e in entries),
            "duplicates": sum(e["status"] == "duplicate" for e in entries)}
