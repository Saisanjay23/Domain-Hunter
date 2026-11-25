"""
Takedown & sharing output for a confirmed impersonation:

  abuse_contacts()   registrar (from the domain RDAP) + hosting provider (IP RDAP) + CDN abuse form
  email_draft()      plain-text abuse report with defanged indicators
  evidence_html()    self-contained evidence report (print to PDF from the browser)
  ioc_txt()/stix()   blocklist and STIX 2.1 bundle of the confirmed / high-risk domains

Nothing here sends anything. The analyst reviews and sends the report.
"""

import html
import ipaddress
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

import requests

from .discovery import HTTP_HEADERS, _vcard_value, rdap_lookup

_IP_BOOTSTRAP: Dict[str, List] = {}
_IP_LOCK = threading.Lock()
_IP_CACHE: Dict[str, Optional[Dict[str, Any]]] = {}

# Reporting channels that accept phishing URLs from anyone. Links verified as of 2026-11.
REPORT_CHANNELS = [
    {"name": "Google Safe Browsing", "url": "https://safebrowsing.google.com/safebrowsing/report_phish/",
     "does": "Warns Chrome, Firefox and Safari users"},
    {"name": "Microsoft SmartScreen", "url": "https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site",
     "does": "Warns Edge and Windows users"},
    {"name": "Netcraft", "url": "https://report.netcraft.com/report", "does": "Takedown and blocklist feeds"},
    {"name": "APWG", "email": "reportphishing@apwg.org", "does": "Anti-Phishing Working Group clearinghouse"},
]

CDN_FORMS = (("cloudflare", "Cloudflare abuse form", "https://abuse.cloudflare.com/"),)


def defang(value: str) -> str:
    return (value or "").replace("http", "hxxp").replace(".", "[.]")


def _utc(ts: Optional[float] = None) -> str:
    return datetime.fromtimestamp(ts or time.time(), timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ------------------------------------------------------------------ IP RDAP
def _ip_service(ip: str) -> Optional[str]:
    version = "ipv6" if ":" in ip else "ipv4"
    with _IP_LOCK:
        if version not in _IP_BOOTSTRAP:
            try:
                data = requests.get(f"https://data.iana.org/rdap/{version}.json", headers=HTTP_HEADERS, timeout=15).json()
                _IP_BOOTSTRAP[version] = data.get("services", [])
            except Exception:
                _IP_BOOTSTRAP[version] = []
    addr = ipaddress.ip_address(ip)
    for prefixes, urls in _IP_BOOTSTRAP[version]:
        for pfx in prefixes:
            if addr in ipaddress.ip_network(pfx, strict=False):
                return next((u for u in urls if u.startswith("https")), urls[0] if urls else None)
    return None


def ip_abuse(ip: str, timeout: int = 12) -> Optional[Dict[str, Any]]:
    """Network owner and abuse contact of an IP address (cached). None if unavailable or not public."""
    if ip in _IP_CACHE:
        return _IP_CACHE[ip]
    out: Optional[Dict[str, Any]] = None
    try:
        if not ipaddress.ip_address(ip).is_global:
            _IP_CACHE[ip] = None
            return None
        base = _ip_service(ip)
        if base:
            data = requests.get(f"{base.rstrip('/')}/ip/{ip}", headers={**HTTP_HEADERS, "Accept": "application/rdap+json"}, timeout=timeout).json()
            out = {"ip": ip, "network": data.get("name"), "handle": data.get("handle"), "country": data.get("country"),
                   "org": None, "abuse_email": None}

            def walk(entities):
                for ent in entities or []:
                    roles = ent.get("roles") or []
                    if "abuse" in roles and not out["abuse_email"]:
                        out["abuse_email"] = _vcard_value(ent, "email")
                    if ("registrant" in roles or "administrative" in roles) and not out["org"]:
                        out["org"] = _vcard_value(ent, "fn")
                    walk(ent.get("entities"))

            walk(data.get("entities"))
    except Exception:
        out = None
    _IP_CACHE[ip] = out
    return out


def abuse_contacts(cand: Dict[str, Any], lookup: bool = True) -> Dict[str, Any]:
    """Who can take this site down: registrar, hosting provider(s), CDN, plus public reporting channels."""
    domain = cand["domain"]
    rd = cand.get("rdap") or {}
    if lookup and not rd:
        rd = rdap_lookup(domain) or {}
    registrar = {"name": rd.get("registrar"), "abuse_email": rd.get("abuse_email"), "created": rd.get("created")}
    hosts: List[Dict[str, Any]] = []
    forms: List[Dict[str, str]] = []
    for ip in ((cand.get("dns") or {}).get("a") or [])[:3]:
        info = ip_abuse(ip) if lookup else None
        if info:
            hosts.append(info)
            label = f"{info.get('network') or ''} {info.get('org') or ''}".lower()
            for key, name, url in CDN_FORMS:
                if key in label and not any(f["url"] == url for f in forms):
                    forms.append({"name": name, "url": url})
    emails = []
    for e in [registrar["abuse_email"]] + [h.get("abuse_email") for h in hosts]:
        if e and e not in emails:
            emails.append(e)
    return {"domain": domain, "registrar": registrar, "hosting": hosts, "forms": forms, "emails": emails,
            "channels": REPORT_CHANNELS}


# ------------------------------------------------------------------ report text
def _facts(cand: Dict[str, Any], brand: str) -> List[str]:
    ev = cand.get("evidence") or {}
    http = ev.get("http") or {}
    dns = cand.get("dns") or {}
    rd = cand.get("rdap") or {}
    lines = [f"Domain: {defang(cand['domain'])}"]
    if http.get("final_url"):
        lines.append(f"URL observed: {defang(http['final_url'])} (HTTP {http.get('status')})")
    if ev.get("title"):
        lines.append(f"Page title: {ev['title']}")
    if dns.get("a"):
        lines.append("IP address(es): " + ", ".join(defang(a) for a in dns["a"]))
    if dns.get("mx"):
        lines.append("Mail servers: " + ", ".join(defang(m) for m in dns["mx"]))
    if rd.get("created"):
        lines.append(f"Registered: {rd['created'][:10]}" + (f" ({rd['age_days']} days ago)" if rd.get("age_days") is not None else ""))
    if rd.get("registrar"):
        lines.append(f"Registrar: {rd['registrar']}")
    return lines


def email_draft(cand: Dict[str, Any], brand: str, contacts: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Plain-text abuse report. Placeholders in [brackets] are for the analyst to fill in."""
    domain = cand["domain"]
    reasons = [r for r in (cand.get("reasons") or [])][:8]
    to = ", ".join((contacts or {}).get("emails") or []) or "[registrar / hosting abuse contact]"
    subject = f"Phishing / brand impersonation: {defang(domain)} (impersonates {brand})"
    body = "\n".join([
        "Hello Abuse Team,",
        "",
        f"We represent {brand} [or: we are reporting on behalf of the rights holder]. The domain below is impersonating "
        f"our brand and appears to be used for phishing or fraud. We ask you to investigate and suspend it.",
        "",
        "INDICATORS",
        *[f"  - {line}" for line in _facts(cand, brand)],
        "",
        "WHY WE BELIEVE IT IS MALICIOUS",
        *([f"  - {r}" for r in reasons] or ["  - Lookalike of the brand domain"]),
        "",
        f"Official brand domain: {brand}",
        "",
        "REQUEST",
        "Please suspend or disable the domain / hosting and confirm the action. We can supply screenshots and further evidence on request.",
        "",
        "Regards,",
        "[Your name]",
        "[Role], [Organisation]",
        "[Contact e-mail / phone]",
        "",
        f"Report generated {_utc()}. Indicators are defanged for safe handling.",
    ])
    return {"to": to, "subject": subject, "body": body}


def evidence_html(cand: Dict[str, Any], brand: str, contacts: Optional[Dict[str, Any]] = None) -> str:
    """Self-contained evidence report: open it and print to PDF."""
    e = html.escape
    ev = cand.get("evidence") or {}
    http = ev.get("http") or {}
    dns = cand.get("dns") or {}
    rd = cand.get("rdap") or {}
    tri = cand.get("triage") or {}
    rows = [("Domain", defang(cand["domain"])), ("Impersonates", brand), ("Risk score", f"{cand.get('score', 0)} / 100"),
            ("Verdict", cand.get("verdict_label") or cand.get("verdict")), ("Detected by", ", ".join(cand.get("sources") or [])),
            ("Case status", (tri.get("status") or "open").replace("_", " ")), ("First seen", _utc(cand["first_seen"]) if cand.get("first_seen") else "")]
    site = [("Final URL", defang(http.get("final_url", ""))), ("HTTP status", http.get("status")), ("Title", ev.get("title")),
            ("Server", http.get("server")), ("Password form", "yes" if ev.get("password_form") else ""),
            ("Favicon identical to brand", "yes" if (ev.get("favicon") or {}).get("exact_match") else ""),
            ("Logo similarity (pHash distance)", ev.get("visual_distance")), ("Shared analytics ID", ", ".join(ev.get("shared_analytics") or [])),
            ("Brand resources hot-linked", ev.get("brand_resources") or "")]
    net = [("A records", ", ".join(defang(a) for a in dns.get("a") or [])), ("MX", ", ".join(dns.get("mx") or [])),
           ("Name servers", ", ".join(dns.get("ns") or [])), ("Registered", (rd.get("created") or "")[:10]),
           ("Registrar", rd.get("registrar")), ("Registrar abuse", rd.get("abuse_email"))]
    if contacts:
        for h in contacts.get("hosting") or []:
            net.append((f"Host {h['ip']}", " / ".join(x for x in (h.get("network"), h.get("org"), h.get("abuse_email")) if x)))

    def table(items):
        return "".join(f"<tr><th>{e(str(k))}</th><td>{e(str(v))}</td></tr>" for k, v in items if v not in (None, ""))

    intel = "".join(f"<li>{e(str(i.get('label') or i.get('match')))} ({e(str(i.get('source')))})"
                    f"{' &middot; ' + e(defang(i['url'])) if i.get('url') else ''}</li>" for i in cand.get("intel") or [])
    icon = f'<img class="icon" src="{e(ev["preview"])}" alt="">' if str(ev.get("preview") or "").startswith("data:image/") else ""
    note = f"<h2>Analyst note</h2><p>{e(tri['note'])}</p>" if tri.get("note") else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Evidence: {e(defang(cand['domain']))}</title>
<style>body{{font:14px/1.5 system-ui,sans-serif;color:#101828;max-width:820px;margin:32px auto;padding:0 20px}}
h1{{font-size:20px;margin:0 0 4px}}h2{{font-size:13px;letter-spacing:.05em;text-transform:uppercase;color:#475467;margin:26px 0 8px;border-bottom:1px solid #e4e7ec;padding-bottom:4px}}
table{{border-collapse:collapse;width:100%}}th{{text-align:left;width:230px;color:#475467;font-weight:500;vertical-align:top;padding:4px 12px 4px 0}}
td{{padding:4px 0;word-break:break-word;font-family:ui-monospace,Consolas,monospace;font-size:13px}}.score{{display:inline-block;background:#fef3f2;color:#d92d20;border:1px solid #fecdca;border-radius:6px;padding:2px 10px;font-weight:700}}
.icon{{width:40px;height:40px;object-fit:contain;border:1px solid #e4e7ec;border-radius:6px;float:right}}li{{margin:3px 0}}.foot{{margin-top:30px;color:#667085;font-size:12px}}
@media print{{body{{margin:0}}}}</style></head><body>
{icon}<h1>Brand impersonation evidence</h1><div><span class="score">{cand.get('score', 0)}</span> &nbsp;{e(defang(cand['domain']))} impersonating {e(brand)}</div>
<h2>Summary</h2><table>{table(rows)}</table>
<h2>Why it was flagged</h2><ul>{''.join(f'<li>{e(r)}</li>' for r in cand.get('reasons') or []) or '<li>No signals recorded</li>'}</ul>
<h2>Website</h2><table>{table(site)}</table>
<h2>Network &amp; registration</h2><table>{table(net)}</table>
{f'<h2>Threat intelligence</h2><ul>{intel}</ul>' if intel else ''}{note}
<p class="foot">Generated {e(_utc())} by Brand Impersonation Hunter. Indicators are defanged (hxxp, [.]). Verify before acting.</p></body></html>"""


# ------------------------------------------------------------------ IOC exports
def select_iocs(cands: Iterable[Dict[str, Any]], min_score: int = 45, statuses: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
    """Candidates worth blocking: risky verdicts at or above min_score, never false positives; or an explicit status list."""
    out = []
    want = set(statuses) if statuses else None
    for c in cands:
        st = (c.get("triage") or {}).get("status", "open")
        if st == "false_positive":
            continue
        if want is not None:
            if st in want:
                out.append(c)
        elif c.get("score", 0) >= min_score and c.get("verdict") in ("phishing", "suspicious", "offline", "parked") or st in ("confirmed", "takedown_sent", "taken_down"):
            out.append(c)
    return sorted(out, key=lambda c: -c.get("score", 0))


def ioc_txt(brand: str, cands: List[Dict[str, Any]]) -> str:
    head = [f"# Brand Impersonation Hunter: lookalike domains for {brand}", f"# Generated {_utc()}", f"# {len(cands)} domains, highest risk first. Not defanged: for blocklists.", ""]
    return "\n".join(head + [c["domain"] for c in cands]) + "\n"


def _stix_escape(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "\\'")


def stix_bundle(brand: str, cands: List[Dict[str, Any]]) -> Dict[str, Any]:
    """STIX 2.1 bundle: one domain-name indicator per candidate (deterministic ids, so re-imports update, not duplicate)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    ns = uuid.UUID("5d0a3a64-6c7e-4c4e-9b0b-3a5f6a1d2e10")
    objects: List[Dict[str, Any]] = []
    for c in cands:
        tri = (c.get("triage") or {}).get("status", "open")
        valid_from = now
        if c.get("first_seen"):
            valid_from = datetime.fromtimestamp(c["first_seen"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": f"indicator--{uuid.uuid5(ns, c['domain'])}",
            "created": now, "modified": now, "name": f"Impersonation of {brand}: {c['domain']}",
            "description": "; ".join((c.get("reasons") or [])[:6]) or "Lookalike of the brand domain",
            "indicator_types": ["malicious-activity"], "pattern": f"[domain-name:value = '{_stix_escape(c['domain'])}']",
            "pattern_type": "stix", "valid_from": valid_from, "confidence": max(0, min(100, int(c.get("score", 0)))),
            "labels": ["brand-impersonation", f"case-{tri}"],
        })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
