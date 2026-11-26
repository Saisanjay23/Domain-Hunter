"""
100% Free Multi-Engine Daily Brand Threat Monitor.

Combines zero-cost intelligence engines (no paid API keys required):
  1. URLScan.io Daily Search (`page.domain` keyword + `page.title` brand-title matching, excluding official domains)
  2. Certificate Transparency (`crt.sh` + `ctlogs.dev` fallback for newly issued lookalike TLS certs)
  3. Free Daily Feeds (`Free Daily NRD` newly registered domains CSV + `OpenPhish` + `Phishing.Database`)
  4. Live Typosquat & Combo DNS + HTTP Probe (live resolving lookalikes and webpage titles)
  5. Optional WhoisXML Brand Alert / Domain Discovery (only runs if a key is explicitly configured & enabled)
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from bs4 import BeautifulSoup

from . import config, feeds, source_events
from .crawler import FaviconCrawler
from .discovery import brand_allowlist, crtsh_search, resolve_domains
from .domain_matcher import classify_candidate, evaluate_domain_match
from .domains import normalize_host, registrable_domain, split_host
from .dorks import build_urlscan_daily_queries, build_whoisxml_daily_spec, decompose_keyword, extract_brand_titles
from .exporter import clean_icon_dict_for_export
from .hasher import make_preview_data_uri
from .permutations import generate_permutations
from .sources import SEARCHERS, SourceError


MATCH_META = {
    "daily_domain": {"platform": "urlscan", "label": "URLScan · Domain Keyword"},
    "daily_title": {"platform": "urlscan", "label": "URLScan · Brand Title"},
    "ct_recent": {"platform": "crt.sh", "label": "crt.sh · New Certificate"},
    "ct_log": {"platform": "crt.sh", "label": "crt.sh · Active CT Log"},
    "nrd_feed": {"platform": "nrd_free", "label": "Free Daily NRD · Newly Registered"},
    "openphish_feed": {"platform": "openphish", "label": "OpenPhish · Live Phishing"},
    "phishingdb_feed": {"platform": "phishingdb", "label": "Phishing.Database · Active Phish"},
    "dns_typo": {"platform": "permutation", "label": "Live Typosquat · Active DNS"},
    "whoisxml_brand": {"platform": "whoisxml", "label": "WhoisXML · Brand Alert"},
    "whoisxml_discovery": {"platform": "whoisxml", "label": "WhoisXML · Domain Discovery"},
}


def _probe_live_title(crawler: Any, domain: str) -> str:
    safe_get = getattr(crawler, "_safe_get", None)
    if not callable(safe_get):
        return ""
    for scheme in ("https", "http"):
        res = safe_get(f"{scheme}://{domain}/", max_bytes=256 * 1024)
        if res and getattr(res, "status", 0) and getattr(res, "content", None):
            try:
                soup = BeautifulSoup(res.content, "html.parser")
                if soup.title:
                    return " ".join(soup.title.get_text(" ", strip=True).split())[:90]
            except Exception:
                pass
            return f"HTTP {res.status}"
    return ""


def run_daily_intel(
    target: str,
    brand_title: Optional[str] = None,
    extra_keywords: Optional[List[str]] = None,
    extra_allowlist: Optional[List[str]] = None,
    lookback_hours: int = 24,
    include_urlscan: bool = True,
    include_ct: bool = True,
    include_feeds: bool = True,
    include_dns: bool = True,
    include_whoisxml: Optional[bool] = None,
    with_typos: bool = True,
    timeout: int = 8,
) -> Dict[str, Any]:
    """
    Runs a fast multi-engine 100% free threat sweep for `target`:
      - URLScan.io daily `page.domain` + `page.title` search (auto-widen to 7d if 24h returns 0)
      - Certificate Transparency logs (`crt.sh` / `ctlogs.dev`)
      - Free Daily NRD CSV + OpenPhish + Phishing.Database
      - Live typosquat DNS + HTTP title verification
      - Optional WhoisXML if configured and enabled
    """
    t0 = time.time()
    crawler = FaviconCrawler(timeout=timeout, include_logos=True, probe_subdomains=False, max_workers=6)
    host, _ = crawler.normalize_target(target)
    host = normalize_host(host)
    apex = registrable_domain(host) or host

    scan = crawler.scan(apex)
    soup = getattr(crawler, "last_soup", None)
    final_host = normalize_host(scan.get("resolved_url") or "")
    allowlist = brand_allowlist(apex, extra=extra_allowlist, final_url_host=final_host)
    allow_set = {d.lower() for d in allowlist}

    dec = decompose_keyword(apex)
    _, label, _ = split_host(apex)
    extra_toks = [k.strip().lower() for k in (extra_keywords or []) if k and k.strip()]
    tokens = list(dict.fromkeys([label] + [t for t in dec["tokens"] if len(t) >= 5 or "-" in t] + extra_toks))

    extra_titles = [brand_title.strip()] if brand_title and brand_title.strip() else []
    brand_titles = extract_brand_titles(apex, soup=soup, extra_titles=extra_titles)

    has_urlscan_key = bool(config.get("URLSCAN_API_KEY"))
    us_size = 250 if has_urlscan_key else 100
    us_daily = build_urlscan_daily_queries(tokens, brand_titles, allowlist, hours=lookback_hours, has_key=has_urlscan_key)
    since_days = max(1, (int(lookback_hours) + 23) // 24)
    since_date = (datetime.now(timezone.utc) - timedelta(days=since_days)).strftime("%Y-%m-%d")

    merged: Dict[str, Dict[str, Any]] = {}
    platform_status: List[Dict[str, Any]] = []

    def is_allowed(raw_host: str) -> bool:
        norm = normalize_host(raw_host).lstrip("*.")
        if not norm or "." not in norm:
            return True
        reg = registrable_domain(norm) or norm
        return reg in allow_set or norm in allow_set

    def record_hit(h: Dict[str, Any], match_key: str, source: str) -> bool:
        raw_host = h.get("host") or ""
        norm = normalize_host(raw_host).lstrip("*.")
        if not norm or "." not in norm:
            return False
        reg = registrable_domain(norm) or norm
        if reg in allow_set or norm in allow_set:
            return False
        extra = h.get("extra") or {}
        entry = merged.get(norm)
        if entry is None:
            entry = merged[norm] = {
                "domain": norm,
                "apex_domain": reg,
                "title": "",
                "description": "",
                "platforms": [],
                "match_types": [],
                "matches": [],
                "url": h.get("url"),
                "result_url": extra.get("result"),
                "screenshot": extra.get("screenshot"),
                "ip": h.get("ip"),
                "asn": extra.get("asn"),
                "country": extra.get("country"),
                "action": extra.get("action") or "",
                "registrar": extra.get("registrar") or "",
                "issuer": extra.get("issuer") or "",
                "fuzzer": extra.get("fuzzer") or "",
                "domain_age_days": extra.get("domain_age_days"),
                "first_seen": h.get("time") or "",
            }
        if source not in entry["platforms"]:
            entry["platforms"].append(source)
        if match_key not in entry["match_types"]:
            entry["match_types"].append(match_key)
        meta = MATCH_META[match_key]
        tag = {"platform": source, "match": match_key, "label": meta["label"]}
        if tag not in entry["matches"]:
            entry["matches"].append(tag)
        if h.get("title") and not entry["title"]:
            entry["title"] = h["title"]
        if h.get("url") and not entry["url"]:
            entry["url"] = h["url"]
        if extra.get("screenshot") and not entry["screenshot"]:
            entry["screenshot"] = extra["screenshot"]
        if extra.get("result") and not entry["result_url"]:
            entry["result_url"] = extra["result"]
        if h.get("ip") and not entry["ip"]:
            entry["ip"] = h["ip"]
        if extra.get("action") and not entry["action"]:
            entry["action"] = extra["action"]
        if extra.get("issuer") and not entry["issuer"]:
            entry["issuer"] = extra["issuer"]
        if extra.get("fuzzer") and not entry["fuzzer"]:
            entry["fuzzer"] = extra["fuzzer"]
        if h.get("time") and (not entry["first_seen"] or h["time"] > entry["first_seen"]):
            entry["first_seen"] = h["time"]
        return True

    # ---- Worker 1: URLScan Daily Domain + Brand Title (with 7d archive fallback if 24h has 0 hits)
    def run_urlscan_task() -> List[Dict[str, Any]]:
        out_status: List[Dict[str, Any]] = []
        us_jobs = []
        if us_daily.get("domain_query"):
            us_jobs.append(("daily_domain", us_daily["domain_query"]))
        if us_daily.get("title_query"):
            us_jobs.append(("daily_title", us_daily["title_query"]))

        total_kept = 0
        any_error = False
        temp_hits: List[tuple] = []
        for mk, q in us_jobs:
            rec = {"source": "urlscan", "match": mk, "label": MATCH_META[mk]["label"], "query": q, "count": 0, "ran": True, "error": None}
            try:
                hits = SEARCHERS["urlscan"](q, us_size) or []
                kept_hits = [h for h in hits if not is_allowed(h.get("host") or "")]
                rec["count"] = len(kept_hits)
                total_kept += len(kept_hits)
                for h in kept_hits:
                    temp_hits.append((h, mk))
            except SourceError as e:
                rec["error"] = str(e)
                any_error = True
            except Exception as e:
                rec["error"] = e.__class__.__name__
                any_error = True
            out_status.append(rec)

        # If strict 24h/72h yielded 0 URLScan hits without errors, check 7-day URLScan index automatically
        if total_kept == 0 and not any_error and lookback_hours < 168:
            us_7d = build_urlscan_daily_queries(tokens, brand_titles, allowlist, hours=168, has_key=has_urlscan_key)
            for idx, (mk, _) in enumerate(us_jobs):
                q7 = us_7d.get("domain_query" if mk == "daily_domain" else "title_query")
                if not q7:
                    continue
                try:
                    hits = SEARCHERS["urlscan"](q7, us_size) or []
                    kept_hits = [h for h in hits if not is_allowed(h.get("host") or "")]
                    if kept_hits:
                        out_status[idx]["count"] = len(kept_hits)
                        out_status[idx]["query"] = q7
                        out_status[idx]["label"] = f"{MATCH_META[mk]['label']} (7d)"
                        for h in kept_hits:
                            temp_hits.append((h, mk))
                except Exception:
                    pass

        return [("urlscan", temp_hits, out_status)]

    # ---- Worker 2: Certificate Transparency (crt.sh + ctlogs.dev fallback)
    def run_ct_task() -> Dict[str, Any]:
        ct_tok = label if len(label) >= 3 else (tokens[0] if tokens else "")
        res = crtsh_search(ct_tok, timeout=15, retries=1, max_hosts=200)
        hosts = res.get("hosts") or {}
        hits = []
        for h_dom, info in sorted(hosts.items(), key=lambda kv: kv[1].get("last_seen") or "", reverse=True):
            if is_allowed(h_dom):
                continue
            ls = info.get("last_seen") or ""
            mk = "ct_recent" if ls and ls >= since_date else "ct_log"
            hits.append((
                {
                    "host": h_dom,
                    "url": f"https://{h_dom}",
                    "time": ls,
                    "title": f"TLS Cert Issued ({info.get('issuer') or 'Public CA'})",
                    "extra": {"issuer": info.get("issuer") or "", "action": "recent cert" if mk == "ct_recent" else "ct cert"},
                },
                mk,
            ))
            if len(hits) >= 80:
                break
        return {
            "hits": hits,
            "status": {
                "source": "crt.sh",
                "match": "ct_recent",
                "label": "crt.sh · Certificate Transparency",
                "query": f"%{ct_tok}%",
                "count": len(hits),
                "ran": True,
                "error": res.get("error"),
            },
        }

    # ---- Worker 3: Free Threat & Daily NRD Feeds (OpenPhish, Phishing.Database, Free Daily NRD)
    def run_feeds_task() -> Dict[str, Any]:
        res = feeds.match(tokens, list(allow_set))
        feed_to_match = {"nrd_free": "nrd_feed", "openphish": "openphish_feed", "phishingdb": "phishingdb_feed"}
        hits = []
        for h in res.get("hits") or []:
            fd = h.get("feed") or "phishingdb"
            mk = feed_to_match.get(fd, "phishingdb_feed")
            hits.append((
                fd,
                mk,
                {
                    "host": h.get("host"),
                    "url": h.get("url") or f"http://{h.get('host')}",
                    "title": f"{h.get('feed_name') or fd} match",
                    "extra": {"action": "newly registered" if fd == "nrd_free" else "active phishing"},
                },
            ))
        statuses = []
        for st in res.get("status") or []:
            fd = st.get("feed") or "phishingdb"
            statuses.append({
                "source": fd,
                "match": feed_to_match.get(fd, "phishingdb_feed"),
                "label": st.get("name") or fd,
                "query": ", ".join(tokens[:4]),
                "count": st.get("count", 0),
                "ran": True,
                "error": st.get("error"),
            })
        return {"hits": hits, "status": statuses}

    # ---- Worker 4: Active Typosquat & Combo DNS + HTTP Probe (100% Free)
    def run_dns_task() -> Dict[str, Any]:
        perms = [
            p for p in generate_permutations(apex, depth="quick", extra_keywords=extra_keywords)
            if not is_allowed(p.get("domain") or "") and p.get("fuzzer") != "original"
        ][:120]
        names = [p["domain"] for p in perms]
        fuzzer_map = {p["domain"]: p.get("fuzzer", "typo") for p in perms}
        dns_res = resolve_domains(names, concurrency=80, timeout=2.0)
        resolving = [
            dom for dom, info in dns_res.items()
            if info.get("registered") and (info.get("a") or info.get("aaaa"))
        ]
        titles: Dict[str, str] = {}
        if resolving:
            with ThreadPoolExecutor(max_workers=8) as p_pool:
                fmap = {p_pool.submit(_probe_live_title, crawler, d): d for d in resolving[:20]}
                for pf in as_completed(fmap):
                    d = fmap[pf]
                    try:
                        titles[d] = pf.result()
                    except Exception:
                        pass
        hits = []
        for dom, info in dns_res.items():
            if not info.get("registered"):
                continue
            ips = info.get("a") or info.get("aaaa") or []
            hits.append({
                "host": dom,
                "ip": ips[0] if ips else None,
                "url": f"https://{dom}" if ips else None,
                "title": titles.get(dom) or (f"Active DNS ({fuzzer_map.get(dom, 'lookalike')})"),
                "extra": {"fuzzer": fuzzer_map.get(dom, ""), "action": "live DNS" if ips else "registered NS/MX"},
            })
        return {
            "hits": hits,
            "status": {
                "source": "permutation",
                "match": "dns_typo",
                "label": "Live Typosquats (Free DNS)",
                "query": f"{len(names)} lookalike permutations probed",
                "count": len(hits),
                "ran": True,
                "error": None,
            },
        }

    # ---- Worker 5: Optional WhoisXML (only if configured and requested)
    def run_whoisxml_task() -> List[Dict[str, Any]]:
        wx_brand_spec = build_whoisxml_daily_spec(tokens, allowlist, since_days=since_days, with_typos=with_typos, mode="brand_alert")
        wx_disc_spec = build_whoisxml_daily_spec(tokens, allowlist, since_days=since_days, with_typos=False, mode="domain_discovery")
        out = []
        for mk, spec in (("whoisxml_brand", wx_brand_spec), ("whoisxml_discovery", wx_disc_spec)):
            rec = {"source": "whoisxml", "match": mk, "label": MATCH_META[mk]["label"], "query": spec, "count": 0, "ran": True, "error": None}
            hits = []
            try:
                raw_hits = SEARCHERS["whoisxml"](spec, 500) or []
                hits = [h for h in raw_hits if not is_allowed(h.get("host") or "")]
                rec["count"] = len(hits)
            except SourceError as e:
                rec["error"] = str(e)
            except Exception as e:
                rec["error"] = e.__class__.__name__
            out.append((rec, hits, mk))
        return out

    run_wx = config.is_enabled("whoisxml") if include_whoisxml is None else bool(include_whoisxml and config.is_enabled("whoisxml"))

    with ThreadPoolExecutor(max_workers=5) as pool:
        futs: Dict[Any, str] = {}
        if include_urlscan:
            futs[pool.submit(run_urlscan_task)] = "urlscan"
        if include_ct:
            futs[pool.submit(run_ct_task)] = "ct"
        if include_feeds:
            futs[pool.submit(run_feeds_task)] = "feeds"
        if include_dns:
            futs[pool.submit(run_dns_task)] = "dns"
        if run_wx:
            futs[pool.submit(run_whoisxml_task)] = "whoisxml"

        for fut in as_completed(futs):
            kind = futs[fut]
            try:
                res = fut.result()
                if kind == "urlscan":
                    for _, temp_hits, statuses in res:
                        platform_status.extend(statuses)
                        for h, mk in temp_hits:
                            record_hit(h, mk, "urlscan")
                elif kind == "ct":
                    platform_status.append(res["status"])
                    for h, mk in res["hits"]:
                        record_hit(h, mk, "crt.sh")
                elif kind == "feeds":
                    platform_status.extend(res["status"])
                    for fd, mk, h in res["hits"]:
                        record_hit(h, mk, fd)
                elif kind == "dns":
                    platform_status.append(res["status"])
                    for h in res["hits"]:
                        record_hit(h, "dns_typo", "permutation")
                elif kind == "whoisxml":
                    for rec, hits, mk in res:
                        platform_status.append(rec)
                        for h in hits:
                            record_hit(h, mk, "whoisxml")
            except Exception as e:
                platform_status.append({"source": kind, "match": kind, "label": kind, "query": "", "count": 0, "ran": True, "error": e.__class__.__name__})

    # Build crisp, bold-ready titles + plain-English descriptions
    results: List[Dict[str, Any]] = []
    for item in merged.values():
        reasons = []
        if "daily_title" in item["match_types"]:
            reasons.append("Live page title matched brand title in URLScan.io")
        if "daily_domain" in item["match_types"]:
            reasons.append("Scanned domain matched brand keyword in URLScan.io")
        if "openphish_feed" in item["match_types"]:
            reasons.append("Listed in OpenPhish live phishing feed")
        if "phishingdb_feed" in item["match_types"]:
            reasons.append("Listed in Phishing.Database active domains")
        if "nrd_feed" in item["match_types"]:
            reasons.append("Appeared in Free Daily Newly Registered Domains feed")
        if "ct_recent" in item["match_types"]:
            iss = f" ({item['issuer']})" if item["issuer"] else ""
            reasons.append(f"New SSL certificate issued recently in CT logs{iss}")
        elif "ct_log" in item["match_types"]:
            iss = f" ({item['issuer']})" if item["issuer"] else ""
            reasons.append(f"Active TLS certificate recorded in crt.sh{iss}")
        if "dns_typo" in item["match_types"]:
            fz = f" ({item['fuzzer']})" if item["fuzzer"] else ""
            ip_note = f" resolving to {item['ip']}" if item["ip"] else " registered in DNS"
            reasons.append(f"Active lookalike permutation{fz}{ip_note}")
        if "whoisxml_brand" in item["match_types"]:
            act = f" ({item['action']})" if item["action"] else ""
            reasons.append(f"Flagged by WhoisXML Brand Alert{act} since {since_date}")
        if "whoisxml_discovery" in item["match_types"]:
            reasons.append(f"Discovered by WhoisXML Domains index since {since_date}")
        mm = evaluate_domain_match(
            item["domain"], apex, keywords=extra_keywords, allowlist=allowlist,
            evidence={"brand_in_title": "daily_title" in item["match_types"]},
            intel=[{"match": mt} for mt in item["match_types"]],
        )
        # Drop pure dictionary-word false positives when no title or feed corroboration exists
        strong_daily = bool(set(item["match_types"]) & {"daily_title", "openphish_feed", "phishingdb_feed", "whoisxml_brand"})
        if mm["is_benign_collision"] and not strong_daily:
            continue
        item["registered_domain"] = mm["registered_domain"]
        item["matching_subdomain"] = mm["matching_subdomain"]
        item["matched_keyword"] = mm["matched_keyword"]
        item["matching_technique"] = mm["matching_technique"]
        item["similarity_percent"] = mm["similarity_percent"]
        item["unicode"] = mm["unicode"]
        item["original_domain"] = apex
        daily_verdict = "phishing" if (set(item["match_types"]) & {"openphish_feed", "phishingdb_feed", "daily_title"}) else ("suspicious" if (mm["is_subdomain_impersonation"] or mm["mixed_script"] or len(item["platforms"]) > 1) else "suspicious")
        # Feed listings and a cloned live title are independent (non-name) evidence; a name match alone is not.
        daily_intel_refs = [{"match": "feed"} for mt in item["match_types"] if mt in ("openphish_feed", "phishingdb_feed")]
        daily_intel_refs += [{"match": "daily_title"} for mt in item["match_types"] if mt == "daily_title"]
        item["classification"] = classify_candidate({"match_meta": mm, "verdict": daily_verdict, "intel": daily_intel_refs}, score=75 if daily_verdict == "phishing" else 50)
        if mm["is_subdomain_impersonation"] and not reasons:
            reasons.append(f"Brand keyword '{mm['matched_keyword']}' impersonated in subdomain '{mm['matching_subdomain']}' of '{mm['registered_domain']}'")
        elif mm["is_subdomain_impersonation"]:
            reasons.insert(0, f"Subdomain '{mm['matching_subdomain']}' impersonates '{mm['matched_keyword']}' on root '{mm['registered_domain']}'")
        item["description"] = " · ".join(reasons)
        if not item["title"]:
            item["title"] = item["domain"]
        results.append(item)

    def _priority(r: Dict[str, Any]):
        mt = set(r["match_types"])
        return (
            -len(r["platforms"]),
            -(2 if mt & {"openphish_feed", "phishingdb_feed", "daily_title", "whoisxml_brand"} else 0),
            -(1 if mt & {"nrd_feed", "ct_recent", "daily_domain", "dns_typo"} else 0),
            r["domain"],
        )

    results.sort(key=_priority)
    for st in platform_status:
        if st.get("ran") and st.get("error"):
            source_events.record(str(st.get("source") or "source"), str(st["error"]), "Daily Radar", label=str(st.get("label") or ""), target=apex)

    icons_out = []
    for ic in scan.get("icons") or []:
        cleaned = clean_icon_dict_for_export(ic)
        cleaned["preview"] = make_preview_data_uri(ic.get("_raw_bytes") or b"", ic.get("format"))
        icons_out.append(cleaned)

    stats = {
        "total_domains": len(results),
        "apex_domains": len({r["apex_domain"] for r in results}),
        "urlscan_hits": sum(1 for r in results if "urlscan" in r["platforms"]),
        "ct_hits": sum(1 for r in results if "crt.sh" in r["platforms"]),
        "feed_hits": sum(1 for r in results if set(r["platforms"]) & {"nrd_free", "openphish", "phishingdb"}),
        "dns_hits": sum(1 for r in results if "permutation" in r["platforms"]),
        "whoisxml_hits": sum(1 for r in results if "whoisxml" in r["platforms"]),
        "both_platforms": sum(1 for r in results if len(r["platforms"]) > 1),
        "daily_domain_hits": sum(1 for r in results if "daily_domain" in r["match_types"]),
        "daily_title_hits": sum(1 for r in results if "daily_title" in r["match_types"]),
        "elapsed_sec": round(time.time() - t0, 1),
    }

    return {
        "target": apex,
        "lookback_hours": lookback_hours,
        "since_date": since_date,
        "free_mode": not run_wx,
        "allowlist": allowlist,
        "tokens": tokens,
        "brand_titles": brand_titles,
        "brand": {
            "domain": apex,
            "resolved_url": scan.get("resolved_url"),
            "reachable": scan.get("reachable"),
            "title": brand_titles[0] if brand_titles else "",
            "icons": icons_out,
        },
        "queries": {
            "urlscan_domain": us_daily.get("domain_query", ""),
            "urlscan_domain_url": us_daily.get("domain_query_url", ""),
            "urlscan_title": us_daily.get("title_query", ""),
            "urlscan_title_url": us_daily.get("title_query_url", ""),
            "urlscan_combined": us_daily.get("combined_query", ""),
            "urlscan_combined_url": us_daily.get("combined_query_url", ""),
        },
        "platforms": platform_status,
        "results": results,
        "stats": stats,
        "sources": config.sources_status(),
    }
