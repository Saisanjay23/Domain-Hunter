"""
Watchlist alerts: decide what is worth telling the analyst about, and deliver it to a webhook.

Only genuinely new, risky lookalikes alert (new since the previous hunt, verdict High risk or
Suspicious, score >= the watch's threshold, not marked false positive). The first hunt of a
brand is a baseline: it is recorded as an info alert but never pings the webhook.
"""

from typing import Any, Dict, List, Optional, Tuple

import requests

from .takedown import defang

RISKY = ("phishing", "suspicious")
HEADERS = {"User-Agent": "brand-impersonation-hunter/1.0", "Content-Type": "application/json"}


def new_risky(result: Dict[str, Any], min_score: int) -> List[Dict[str, Any]]:
    out = [c for c in result.get("candidates") or []
           if c.get("is_new") and c.get("verdict") in RISKY and c.get("score", 0) >= min_score
           and (c.get("triage") or {}).get("status", "open") != "false_positive"]
    return sorted(out, key=lambda c: -c.get("score", 0))


def compose(brand: str, result: Dict[str, Any], min_score: int) -> Optional[Dict[str, Any]]:
    """Returns {"level", "title", "body", "domains", "notify"} or None when there is nothing to report."""
    stats = result.get("stats") or {}
    cands = result.get("candidates") or []
    if not stats.get("has_previous"):
        risky = [c for c in cands if c.get("verdict") in RISKY and c.get("score", 0) >= min_score]
        return {"level": "info", "notify": False, "domains": [],
                "title": f"Baseline recorded for {brand}",
                "body": f"{len(cands)} registered lookalikes, {stats.get('high_risk', 0)} high risk and {stats.get('suspicious', 0)} suspicious. "
                        f"{len(risky)} are at or above your threshold ({min_score}). Future hunts will alert on new ones only."}
    new = new_risky(result, min_score)
    if not new:
        return None
    high = [c for c in new if c.get("verdict") == "phishing"]
    lines = [f"- {c['score']:>3}  {defang(c['domain'])}  {c.get('verdict_label', c.get('verdict'))}"
             + (f": {(c.get('reasons') or [''])[0]}" if c.get("reasons") else "") for c in new[:10]]
    if len(new) > 10:
        lines.append(f"- ... and {len(new) - 10} more")
    return {"level": "high" if high else "medium", "notify": True, "domains": [c["domain"] for c in new],
            "title": f"{len(new)} new lookalike domain{'s' if len(new) != 1 else ''} for {brand}"
                     + (f" ({len(high)} high risk)" if high else ""),
            "body": "\n".join(lines)}


def send_webhook(url: str, title: str, body: str, data: Optional[Dict[str, Any]] = None, timeout: int = 10) -> Tuple[bool, str]:
    """
    POSTs JSON with `text` (Slack, Teams, Mattermost) and `content` (Discord) plus structured fields.
    The URL is never included in the returned message (it usually embeds a secret token).
    """
    payload = {"text": f"{title}\n{body}", "content": f"**{title}**\n{body}"[:1900], "title": title, "body": body, **(data or {})}
    try:
        r = requests.post(url, json=payload, headers=HEADERS, timeout=timeout)
    except requests.RequestException as e:
        return False, f"webhook unreachable ({e.__class__.__name__})"
    if r.status_code >= 400:
        return False, f"webhook rejected the message (HTTP {r.status_code})"
    return True, f"delivered (HTTP {r.status_code})"
