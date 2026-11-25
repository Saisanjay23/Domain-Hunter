from typing import List, Dict, Any, Iterable, Optional

from .platforms import (
    CENSYS_FAVICON_MD5_FIELDS,
    CENSYS_FAVICON_SHA256_FIELD,
    cenql_any,
)


def _unique(values: Iterable[Any]) -> List[Any]:
    return list(dict.fromkeys(v for v in values if v is not None and v != ""))


def _is_favicon_like(icon: Dict[str, Any]) -> bool:
    """
    Favicon-hash filters (FOFA icon_hash, Shodan http.favicon.hash, Censys favicons.*)
    only index a site's favicon, so brand logos / og:images are never matched there.
    Icons without a 'kind' (e.g. a user-supplied image) are assumed to be favicons.
    """
    return icon.get("kind", "favicon") != "logo"


def _is_master_favicon(icon: Dict[str, Any]) -> bool:
    """
    Icons eligible for the combined master queries. Subdomain-probe favicons are kept
    out: portals like careers./login./mail. are often CNAMEd to SaaS vendors (Workday,
    SuccessFactors, Okta, ...) whose shared favicon would flood the master query with
    every other customer of that vendor. They still get individual queries.
    """
    return icon.get("kind", "favicon") in ("favicon", "app-icon")


def fofa_icon_query(mmh3_values: List[int]) -> str:
    if len(mmh3_values) == 1:
        return f'icon_hash="{mmh3_values[0]}"'
    return "(" + " || ".join(f'icon_hash="{h}"' for h in mmh3_values) + ")"


def shodan_icon_query(mmh3_values: List[int]) -> str:
    # Shodan ORs comma-separated filter values; spaces are not allowed between them.
    return "http.favicon.hash:" + ",".join(str(h) for h in mmh3_values)


def censys_md5_query(md5_values: List[str]) -> str:
    return " or ".join(cenql_any(f, md5_values) for f in CENSYS_FAVICON_MD5_FIELDS)


def censys_sha256_query(sha_values: List[str]) -> str:
    return cenql_any(CENSYS_FAVICON_SHA256_FIELD, sha_values)


def urlscan_hash_query(sha_values: List[str]) -> str:
    if len(sha_values) == 1:
        return f"hash:{sha_values[0]}"
    return "hash:(" + " OR ".join(sha_values) + ")"


def generate_search_queries(icons_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generates OSINT / threat intel search queries for FOFA, Shodan, Censys and URLScan.
    Deduplicates identical hashes across icons.

    - FOFA:    icon_hash="<mmh3>"
    - Shodan:  http.favicon.hash:<mmh3>            (multi: hash1,hash2)
    - Censys:  CenQL favicons.hash_md5 / hash_sha256 on hosts + web properties
    - URLScan: hash:<sha256>                       (any resource loaded by a scanned page)

    Returns per-icon query lists plus a "combined" dict of OR-ed master queries.
    """
    favicons = [i for i in icons_data if _is_favicon_like(i)]
    master = [i for i in icons_data if _is_master_favicon(i)]

    all_mmh3 = _unique(i.get("mmh3") for i in favicons)
    mmh3_vals = _unique(i.get("mmh3") for i in master)
    md5_vals = _unique(i.get("md5") for i in master)
    sha_fav_vals = _unique(i.get("sha256") for i in master)
    sha_all_vals = _unique(i.get("sha256") for i in icons_data if i.get("kind") != "subdomain")
    sha_listed = _unique(i.get("sha256") for i in icons_data)

    fofa_queries = [fofa_icon_query([h]) for h in all_mmh3]
    shodan_queries = [shodan_icon_query([h]) for h in all_mmh3]
    censys_queries: List[str] = []
    for icon in favicons:
        md5, sha = icon.get("md5"), icon.get("sha256")
        if md5 and censys_md5_query([md5]) not in censys_queries:
            censys_queries.append(censys_md5_query([md5]))
        if sha and censys_sha256_query([sha]) not in censys_queries:
            censys_queries.append(censys_sha256_query([sha]))
    urlscan_queries = [urlscan_hash_query([s]) for s in sha_listed]

    combined: Dict[str, str] = {}
    if mmh3_vals:
        combined["fofa"] = fofa_icon_query(mmh3_vals)
        combined["shodan"] = shodan_icon_query(mmh3_vals)
    if md5_vals:
        combined["censys"] = censys_md5_query(md5_vals)
        combined["censys_md5"] = combined["censys"]
    if sha_fav_vals:
        combined["censys_sha256"] = censys_sha256_query(sha_fav_vals)
    if sha_all_vals:
        combined["urlscan"] = urlscan_hash_query(sha_all_vals)

    return {
        "fofa": fofa_queries,
        "shodan": shodan_queries,
        "censys": censys_queries,
        "urlscan": urlscan_queries,
        "combined": combined,
        "hash_counts": {
            "mmh3": len(mmh3_vals),
            "md5": len(md5_vals),
            "sha256": len(sha_all_vals),
            "excluded_subdomain_icons": len([i for i in icons_data if i.get("kind") == "subdomain"]),
        },
    }


def build_multi_hash_queries(
    mmh3_hashes: List[Any],
    md5_hashes: Optional[List[str]] = None,
    sha256_hashes: Optional[List[str]] = None,
) -> Dict[str, str]:
    """
    Given arbitrary lists of hashes, generates unified Boolean OR master queries:
    MMH3 -> FOFA + Shodan, MD5 -> Censys, SHA256 -> URLScan (+ Censys web properties).
    """
    clean_mmh3: List[int] = []
    for h in mmh3_hashes or []:
        try:
            clean_mmh3.append(int(h))
        except (ValueError, TypeError):
            continue
    mmh3_vals = _unique(clean_mmh3)
    md5_vals = _unique(str(h).lower() for h in (md5_hashes or []))
    sha_vals = _unique(str(h).lower() for h in (sha256_hashes or []))

    queries: Dict[str, str] = {}
    if mmh3_vals:
        queries["fofa"] = fofa_icon_query(mmh3_vals)
        queries["shodan"] = shodan_icon_query(mmh3_vals)
    if md5_vals:
        queries["censys"] = censys_md5_query(md5_vals)
    if sha_vals:
        queries["urlscan"] = urlscan_hash_query(sha_vals)
        queries["censys_sha256"] = censys_sha256_query(sha_vals)
    return queries
