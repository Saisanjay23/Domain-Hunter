"""
Keyword decomposition, brand-title extraction, and OSINT dork builders
for FOFA, Censys, URLScan (including 24h daily domain/title searches),
Shodan, WhoisXML, crt.sh, and search engines.
"""

import json
import re
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from bs4 import BeautifulSoup

from .domains import looks_like_domain, registrable_domain, split_host
from .permutations import (
    UNICODE_GLYPHS,
    homoglyph_ascii,
    omission,
    repetition,
    replacement,
    transposition,
    vowel_swap,
)
from .platforms import (
    build_censys_search_url,
    build_crtsh_search_url,
    build_fofa_search_url,
    build_shodan_search_url,
    build_urlscan_search_url,
    cenql_any,
    cenql_quote,
    quote_term,
    urlscan_exclude_clause,
)

# Words that never identify a brand on their own; a host wildcard on them matches millions of sites.
STOP_WORDS = {
    "the", "and", "for", "of", "in", "on", "at", "by", "to", "a", "an", "&",
    "ltd", "pvt", "inc", "corp", "co", "llc", "plc", "gmbh", "ag", "sa", "bv", "limited", "private",
    "company", "corporation", "group", "holdings", "com", "org", "net", "www", "official",
}
GENERIC_WORDS = {
    "bank", "online", "global", "international", "india", "services", "service", "solutions",
    "systems", "technologies", "technology", "tech", "digital", "network", "secure", "login",
    "account", "app", "web", "site", "home", "new", "real", "estate", "realty", "homes",
    "projects", "project", "city", "park", "tower", "towers", "residency", "phase",
    "card", "cards", "wallet", "pay", "cash", "money", "fund", "funds", "loan", "loans",
    "capital", "finance", "financial", "credit", "insurance", "motors", "power", "energy",
    "direct", "connect", "express", "mobile", "cloud", "mail", "portal", "support", "help",
    "care", "store", "shop", "club", "hub", "center", "centre", "live", "life", "world",
    "plus", "prime", "smart", "auto", "gold", "safe", "trust", "security", "verify", "auth",
}
SHORT_NOISE_WORDS = {
    "the", "and", "for", "new", "old", "top", "big", "one", "two", "pro", "app", "web", "net",
    "buy", "get", "pay", "all", "max", "hot", "red", "sun", "air", "car", "tax", "law", "oil",
    "gas", "bio", "eco", "med", "fin", "dev", "ops", "ion", "hub", "box", "lab", "fit", "fun",
    "art", "day", "way", "run", "set", "map", "doc", "bit", "dot", "key", "tag", "use", "try",
    "see", "our", "out", "off", "now", "can", "may",
}

MIN_TOKEN_LEN = 4         # shorter tokens (co, de, gi, at) match nearly every hostname
MIN_ABBREV_TOKEN_LEN = 3  # acronyms / X&Y abbreviations such as sbi, lnt, att

_ABBREV_RE = re.compile(r"^([a-z]{1,4})&([a-z]{1,4})$", re.I)

WAF_OR_GENERIC_TITLES = {
    "home", "welcome", "index", "login", "sign in", "official site", "official website",
    "just a moment...", "just a moment", "attention required! | cloudflare", "access denied",
    "403 forbidden", "404 not found", "error", "loading...", "please wait", "checking your browser",
}

SCAM_LURE_URL_TERMS = [
    "login", "signin", "verify", "secure", "auth", "account", "update", "kyc",
    "support", "refund", "claim", "wallet", "official", "portal", "pay", "offer",
    "booking", "careers",
]
SCAM_LURE_TITLE_TERMS = [
    "login", "verify", "secure", "account", "kyc", "update", "support",
    "refund", "claim", "official", "portal", "offer", "booking", "wallet",
]
SCAM_LURE_BODY_TERMS = ["password", "otp", "seed phrase", "wallet"]

FREE_HOSTING = [
    "pages.dev", "workers.dev", "r2.dev", "netlify.app", "vercel.app", "web.app", "firebaseapp.com", "github.io",
    "gitlab.io", "herokuapp.com", "onrender.com", "glitch.me", "replit.app", "repl.co", "blogspot.com",
    "wordpress.com", "wixsite.com", "weebly.com", "webflow.io", "square.site", "godaddysites.com", "framer.app",
    "carrd.co", "notion.site", "myshopify.com", "000webhostapp.com", "ngrok-free.app", "ngrok.io", "azurewebsites.net",
    "web.core.windows.net", "s3.amazonaws.com", "ipfs.io", "dweb.link", "surge.sh", "fly.dev", "translate.goog",
    "trycloudflare.com", "canva.site", "duckdns.org", "ddns.net",
]
CLOUD_ABUSE_DOMAINS = FREE_HOSTING[:22]
SOCIAL = ["facebook.com", "instagram.com", "x.com", "twitter.com", "t.me", "linkedin.com", "youtube.com", "tiktok.com", "whatsapp.com"]
APP_STORES = ["play.google.com", "apps.apple.com", "apkpure.com", "apkcombo.com", "uptodown.com", "apkmirror.com"]
PASTE_SITES = ["pastebin.com", "paste.ee", "justpaste.it", "rentry.co", "ghostbin.site", "controlc.com"]

ENGINES = {
    "google": "https://www.google.com/search?q={}",
    "bing": "https://www.bing.com/search?q={}",
    "duckduckgo": "https://duckduckgo.com/?q={}",
    "yandex": "https://yandex.com/search/?text={}",
}


def sanitize_keywords(raw_input: str) -> List[str]:
    """
    Parses keywords from comma-separated or newline-delimited strings,
    stripping URLs, schemes, quotes, and whitespace while preserving multi-word phrases.
    """
    if not raw_input:
        return []

    cleaned: List[str] = []
    seen = set()
    for t in re.split(r"[\r\n,;|]+", raw_input):
        item = t.strip().strip("'\"`").strip()
        if not item:
            continue
        if re.match(r"^[a-z][a-z0-9+.-]*://", item, re.I):
            try:
                parsed = urllib.parse.urlparse(item)
                item = parsed.netloc or parsed.path
            except Exception:
                pass
        elif looks_like_domain(item.split("/")[0]) and " " not in item:
            item = item.split("/")[0]
        if "@" in item and " " not in item:
            item = item.rsplit("@", 1)[-1]
        item = re.sub(r":\d+$", "", item)
        item = re.sub(r"^www\.", "", item, flags=re.IGNORECASE)
        item = re.sub(r"\s+", " ", item).strip("/").strip(". ").strip()
        if item and item.lower() not in seen:
            seen.add(item.lower())
            cleaned.append(item)
    return cleaned


def _dedupe(items: List[str]) -> List[str]:
    out, seen = [], set()
    for it in items:
        if it and it.lower() not in seen:
            seen.add(it.lower())
            out.append(it)
    return out


def _is_abbreviation(word: str) -> bool:
    return bool(_ABBREV_RE.match(word)) or (word.isupper() and word.isalpha() and 2 <= len(word) <= 5)


def _abbrev_tokens(word: str) -> List[str]:
    m = _ABBREV_RE.match(word)
    if m:
        a, b = m.group(1).lower(), m.group(2).lower()
        cands = [f"{a}n{b}", f"{a}{b}"]
    else:
        cands = [word.lower()]
    return [c for c in cands if len(c) >= MIN_ABBREV_TOKEN_LEN]


def _hyphen_splits(token: str) -> List[str]:
    t = token.lower()
    if len(t) < 6 or "-" in t or not t.isalpha():
        return []
    mid = len(t) // 2
    splits = [f"{t[:mid]}-{t[mid:]}"]
    if len(t) >= 7 and mid != 3:
        splits.append(f"{t[:3]}-{t[3:]}")
    return _dedupe(splits)


def _punycode_skeletons(tokens: List[str], limit: int = 8) -> List[str]:
    skels: List[str] = []
    seen = set()
    for tok in tokens:
        clean = tok.lower().replace("-", "")
        if len(clean) < 5 or not clean.isalnum():
            continue
        for i, ch in enumerate(clean):
            if ch not in UNICODE_GLYPHS:
                continue
            skel = clean[:i] + clean[i + 1:]
            if len(skel) >= 4 and skel not in seen:
                seen.add(skel)
                skels.append(skel)
                if len(skels) >= limit:
                    return skels
    return skels


def _generate_token_variants(tokens: List[str], limit: int = 16) -> List[str]:
    existing = {t.lower() for t in tokens}
    variants: List[str] = []
    seen = set(existing)

    def add(cand: str) -> bool:
        c = cand.lower().strip("-")
        if len(c) < 4 or c in seen or not re.match(r"^[a-z0-9-]+$", c):
            return False
        seen.add(c)
        variants.append(c)
        return len(variants) >= limit

    for tok in tokens:
        clean = tok.lower()
        if len(clean) < 5 or not clean.replace("-", "").isalnum():
            continue
        generators = [
            homoglyph_ascii(clean),
            _hyphen_splits(clean),
            transposition(clean),
            repetition(clean),
            vowel_swap(clean),
        ]
        if len(clean) >= 6:
            generators.append(omission(clean))
        generators.append(replacement(clean))
        for gen in generators:
            for cand in gen:
                if add(cand):
                    return variants
    return variants


def _substring_minimal(terms: List[str]) -> List[str]:
    cleaned = _dedupe([t.lower() for t in terms if t])
    out = [t for t in cleaned if not any(other != t and other in t for other in cleaned)]
    return out or cleaned


def decompose_keyword(raw: str, include_variants: bool = False) -> Dict[str, Any]:
    """
    Decomposes a brand keyword, project name, or domain into titles, DNS-safe hostname
    tokens, compound slugs, co-occurrence groups, Punycode skeletons, optional variants,
    and an optional legit_domain to exclude.
    """
    raw = re.sub(r"\s+", " ", raw.strip())
    raw = re.sub(r"\b([A-Za-z]{1,4})\s*&\s*([A-Za-z]{1,4})\b", r"\1&\2", raw)
    is_domain = looks_like_domain(raw)

    titles: List[str] = []
    tokens: List[str] = []
    compound_slugs: List[str] = []
    cooccurrence_groups: List[List[str]] = []
    project_slug: Optional[str] = None
    compact_slug: Optional[str] = None
    legit_domain: Optional[str] = None

    if is_domain:
        _, label, _ = split_host(raw)
        legit_domain = registrable_domain(raw)
        titles = [label]
        parts = [p for p in label.split("-") if p]
        tokens = [label]
        if len(parts) > 1:
            joined = "".join(parts)
            tokens.append(joined)
            tokens.extend(p for p in parts if len(p) >= MIN_TOKEN_LEN and p not in STOP_WORDS | GENERIC_WORDS)
            compound_slugs = _dedupe([label, joined, "_".join(parts)])
    else:
        titles = [raw]
        words = raw.split(" ")
        if len(words) >= 2 and _is_abbreviation(words[0]):
            rest = words[1:]
            if any(w.lower() not in STOP_WORDS | GENERIC_WORDS for w in rest):
                titles.append(" ".join(rest))

        abbrev_toks: List[str] = []
        anchor_toks: List[str] = []
        word_toks: List[str] = []
        all_alpha_toks: List[str] = []
        full_slug_parts: List[str] = []

        for idx, w in enumerate(words):
            if _is_abbreviation(w):
                abbs = _abbrev_tokens(w)
                abbrev_toks.extend(abbs)
                if abbs:
                    full_slug_parts.append(abbs[0])
                    all_alpha_toks.append(abbs[0])
                continue
            clean = re.sub(r"[^a-z0-9-]", "", w.lower()).strip("-")
            if not clean:
                continue
            all_alpha_toks.append(clean)
            if clean not in STOP_WORDS:
                word_toks.append(clean)
                full_slug_parts.append(clean)
                if idx == 0 and len(clean) == MIN_ABBREV_TOKEN_LEN and clean not in GENERIC_WORDS and clean not in SHORT_NOISE_WORDS:
                    anchor_toks.append(clean)

        distinctive = [w for w in word_toks if len(w) >= MIN_TOKEN_LEN and w not in GENERIC_WORDS]
        tokens = _dedupe(abbrev_toks + anchor_toks + distinctive)

        if len(word_toks) >= 2:
            project_slug = "-".join(word_toks)
            compact_slug = "".join(word_toks)
        elif len(full_slug_parts) >= 2:
            project_slug = "-".join(full_slug_parts)
            compact_slug = "".join(full_slug_parts)

        if len(full_slug_parts) >= 2:
            compound_slugs.extend(["".join(full_slug_parts), "-".join(full_slug_parts), "_".join(full_slug_parts)])
        if project_slug and compact_slug:
            compound_slugs.extend([compact_slug, project_slug, project_slug.replace("-", "_")])
        if len(full_slug_parts) >= 3:
            compound_slugs.extend(["".join(full_slug_parts[:2]), "-".join(full_slug_parts[:2])])
        if len(all_alpha_toks) >= 2 and all_alpha_toks != full_slug_parts:
            compound_slugs.extend(["".join(all_alpha_toks), "-".join(all_alpha_toks)])

        if not tokens:
            if len(full_slug_parts) >= 2:
                tokens = _dedupe(["".join(full_slug_parts), "-".join(full_slug_parts)])
                pair_terms = [t for t in full_slug_parts if len(t) >= MIN_ABBREV_TOKEN_LEN][:3]
                if len(pair_terms) >= 2:
                    cooccurrence_groups.append(pair_terms)
            else:
                tokens = [w for w in word_toks if len(w) >= MIN_ABBREV_TOKEN_LEN] or [re.sub(r"[^a-z0-9]", "", raw.lower())]
        elif len(full_slug_parts) >= 2:
            pair_terms = [t for t in full_slug_parts if len(t) >= MIN_ABBREV_TOKEN_LEN][:3]
            if len(pair_terms) >= 2 and any(p not in tokens for p in pair_terms):
                cooccurrence_groups.append(pair_terms)

    tokens = _dedupe([t for t in tokens if t])
    compound_slugs = _dedupe([s for s in compound_slugs if s and s not in {t.lower() for t in tokens}])
    return {
        "raw": raw,
        "is_domain": is_domain,
        "titles": _dedupe(titles),
        "tokens": tokens,
        "project_slug": project_slug,
        "compact_slug": compact_slug,
        "compound_slugs": compound_slugs,
        "cooccurrence_groups": cooccurrence_groups,
        "punycode_skeletons": _punycode_skeletons(tokens),
        "variants": _generate_token_variants(tokens) if include_variants else [],
        "legit_domain": legit_domain,
    }


def extract_brand_titles(
    domain: str,
    soup: Optional[BeautifulSoup] = None,
    extra_titles: Optional[List[str]] = None,
) -> List[str]:
    """
    Extracts clean brand-title strings suitable for `page.title:` impersonation matching.
    Pulls from <title>, og:site_name, application-name, JSON-LD Organization.name, plus
    the domain label, while rejecting generic WAF / error titles.
    """
    candidates: List[str] = []

    def add(val: Optional[str]) -> None:
        text = re.sub(r"\s+", " ", (val or "").strip())
        if not text or len(text) < 3 or len(text) > 70:
            return
        low = text.lower()
        if low in WAF_OR_GENERIC_TITLES or any(w in low for w in ("cloudflare", "access denied", "403 forbidden", "404 not found", "just a moment")):
            return
        if text not in candidates and low not in {c.lower() for c in candidates}:
            candidates.append(text)

    for t in extra_titles or []:
        add(t)

    if soup is not None:
        for prop, attr in (("og:site_name", "property"), ("application-name", "name")):
            meta = soup.find("meta", attrs={attr: prop})
            if meta and meta.get("content"):
                add(meta["content"])

        for script in soup.find_all("script", attrs={"type": re.compile(r"ld\+json", re.I)}):
            try:
                data = json.loads(script.string or "")
            except Exception:
                continue
            stack = [data]
            while stack:
                node = stack.pop()
                if isinstance(node, list):
                    stack.extend(node)
                elif isinstance(node, dict):
                    if node.get("@type") in ("Organization", "WebSite", "Brand") and isinstance(node.get("name"), str):
                        add(node["name"])
                    stack.extend(v for v in node.values() if isinstance(v, (dict, list)))

        if soup.title:
            raw_title = re.sub(r"\s+", " ", soup.title.get_text(" ", strip=True))
            segments = [s.strip() for s in re.split(r"\s*[|–—•:]\s*|\s+-\s+", raw_title) if s.strip()]
            # Keep the primary title segment (the brand itself, e.g. "Giesecke+Devrient"),
            # skipping trailing marketing taglines (e.g. "SecurityTech", "Solutions").
            if segments:
                first_seg = segments[0]
                if first_seg.lower() not in WAF_OR_GENERIC_TITLES and len(first_seg.split()) <= 5:
                    add(first_seg)
            if len(raw_title) <= 50 and raw_title.lower() not in WAF_OR_GENERIC_TITLES:
                add(raw_title)

    _, label, _ = split_host(domain)
    if label:
        add(label)
        flat = label.replace("-", "")
        if "-" in label and len(flat) >= 5:
            add(flat)

    return candidates[:6]


def _or(items: List[str], sep: str) -> str:
    joined = sep.join(items)
    return f"({joined})" if len(items) > 1 else joined


def _re_escape(value: str) -> str:
    return re.sub(r"([.+*?^$()\[\]{}|\\-])", r"\\\1", value)


def _cenql_regex_contains(field: str, terms: List[str], prefix: str = ".*", suffix: str = ".*") -> str:
    escaped = [_re_escape(t) for t in terms if t]
    pattern = escaped[0] if len(escaped) == 1 else f"({'|'.join(escaped)})"
    return f"{field} =~ {cenql_quote(f'(?i){prefix}{pattern}{suffix}')}"


def _cenql_domain_exclude(legit_domains: List[str]) -> str:
    if not legit_domains:
        return ""
    escaped = [_re_escape(d) for d in legit_domains]
    alt = escaped[0] if len(escaped) == 1 else f"({'|'.join(escaped)})"
    pat = cenql_quote(f"(?i)(^|\\.){alt}$")
    return f" and not (web.hostname =~ {pat} or host.dns.names =~ {pat})"


def _pack(d: Dict[str, str], builder) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, q in d.items():
        if q:
            out[k] = q
            out[f"{k}_url"] = builder(q)
    return out


def build_urlscan_daily_queries(
    tokens: List[str],
    brand_titles: List[str],
    allowlist: List[str],
    hours: int = 24,
    has_key: bool = False,
) -> Dict[str, str]:
    """
    Constructs 100% free-tier-compatible URLScan.io daily search queries (last `hours`h) for:
      1. page.domain keyword matching (filtering out short 4-char split shards like 'gide' that match unrelated words)
      2. page.title brand-title matching
      3. combined daily rule
    strictly excluding all domains in `allowlist` (e.g. gi-de.com).
    """
    raw_toks = _dedupe([t.strip().lower() for t in (tokens or []) if t and t.strip()])
    primary = raw_toks[:1]
    extra_clean = [t for t in raw_toks[1:] if len(t) >= 5 or "-" in t]
    clean_tokens = _dedupe(primary + extra_clean)[:6]
    clean_titles = _dedupe([t for t in (brand_titles or []) if t and len(t.strip()) >= 4])[:6]
    excl = urlscan_exclude_clause(allowlist)
    date_filter = f"date:>now-{max(1, int(hours))}h"

    dom_clauses: List[str] = []
    for t in clean_tokens:
        dom_clauses.append(f"page.domain:{t}.*")
        dom_clauses.append(f"page.domain:{t}*")
        dom_clauses.append(f"page.url:{t}*")
    dom_expr = _or(_dedupe(dom_clauses), " OR ") if dom_clauses else ""

    title_clauses = [f"page.title:{quote_term(t)}" for t in clean_titles]
    title_expr = _or(_dedupe(title_clauses), " OR ") if title_clauses else ""

    domain_query = f"{dom_expr} AND {date_filter}{excl}" if dom_expr else ""
    title_query = f"{title_expr} AND {date_filter}{excl}" if title_expr else ""
    if dom_expr and title_expr:
        combined_query = f"({dom_expr} OR {title_expr}) AND {date_filter}{excl}"
    else:
        combined_query = domain_query or title_query

    return _pack({
        "domain_query": domain_query,
        "title_query": title_query,
        "combined_query": combined_query,
    }, build_urlscan_search_url)


def build_whoisxml_daily_spec(
    tokens: List[str],
    allowlist: List[str],
    since_days: int = 1,
    with_typos: bool = True,
    mode: str = "both",
) -> str:
    """Builds a structured WhoisXML search specification string for SOURCE/hunter pipelines."""
    since = (datetime.now(timezone.utc) - timedelta(days=max(1, min(14, int(since_days))))).strftime("%Y-%m-%d")
    clean_terms = _dedupe([t for t in (tokens or []) if t and len(t.strip()) >= 3])[:3]
    return json.dumps({
        "mode": mode,
        "terms": clean_terms,
        "since_date": since,
        "with_typos": bool(with_typos),
        "allowlist": list(allowlist or [])[:10],
    })


def _build_platform_dorks(
    titles: List[str],
    title_terms: List[str],
    tokens: List[str],
    host_terms: List[str],
    substring_terms: List[str],
    puny_skels: List[str],
    coocc: List[List[str]],
    legit_domains: List[str],
    best_title: str,
    primary_token: str,
    body_titles: List[str],
    is_multi: bool = False,
) -> Dict[str, Dict[str, str]]:
    """Shared builder producing per-keyword and multi-keyword dorks across FOFA, Censys, URLScan, Shodan."""
    # ---------------------------------------------------------------- FOFA
    fofa_excl = "".join(f' && domain!="{d}"' for d in legit_domains)
    fofa_title = _or([f"title={quote_term(t)}" for t in titles], " || ")
    fofa_host = _or([f"host={quote_term(t)}" for t in host_terms], " || ")
    fofa_domain = _or([f"domain={quote_term(t)}" for t in host_terms], " || ")
    fofa_cert = _or([f"cert={quote_term(t)}" for t in _dedupe(tokens + [v for v in host_terms if v in substring_terms])], " || ")
    fofa_body = _or([f"body={quote_term(t)}" for t in titles], " || ")

    fofa_host_contains = _or([f'host*="*{t}*"' for t in substring_terms], " || ")
    fofa_coocc = ["(" + " && ".join(f'host*="*{w}*"' for w in g) + ")" for g in coocc]
    fofa_all_parts = (
        [f'domain*="*{t}*"' for t in substring_terms]
        + [f'host*="*{t}*"' for t in substring_terms]
        + [f'cert*="*{t}*"' for t in substring_terms]
        + [f'cname*="*{t}*"' for t in substring_terms]
        + fofa_coocc
    )
    fofa_deep_parts = (
        fofa_all_parts
        + [f'title*="*{t}*"' for t in _dedupe(titles + substring_terms)]
        + [f'body*="*{t}*"' for t in _dedupe(titles + substring_terms)]
        + [f'header*="*{t}*"' for t in substring_terms]
    )

    fofa_master = f"{fofa_host} && is_domain=true{fofa_excl}" if is_multi else f"({fofa_title} || {fofa_host} || {fofa_domain} || {fofa_cert}) && is_domain=true{fofa_excl}"
    fofa_lure_targets = _or([f'host*="*{t}*"' for t in substring_terms] + [f'title*="*{t}*"' for t in title_terms] + [f'body*="*{t}*"' for t in title_terms], " || ")
    fofa_lure_hooks = _or(
        [f'title*="*{w}*"' for w in ("login", "verify", "secure", "kyc", "support", "official")] + [f'body*="*{w}*"' for w in SCAM_LURE_BODY_TERMS],
        " || ",
    )
    fofa_cloud_hosts = _or([f'domain="{d}"' for d in CLOUD_ABUSE_DOMAINS[:15]], " || ")
    fofa_idn_parts = [f'host*="*{s}*"' for s in puny_skels] + [f'title*="*{t}*"' for t in title_terms] + [f'body*="*{t}*"' for t in title_terms]

    fofa = _pack({
        "all_domains": f"({' || '.join(fofa_all_parts)}) && is_domain=true{fofa_excl}",
        "exhaustive": f"({' || '.join(fofa_deep_parts)}) && is_domain=true{fofa_excl}",
        "scam_lures": f"({fofa_lure_targets}) && ({fofa_lure_hooks}) && is_domain=true{fofa_excl}",
        "free_hosting": f"({fofa_cloud_hosts}) && ({fofa_lure_targets})",
        "idn_homoglyph": f'(host*="xn--" && ({" || ".join(fofa_idn_parts)})) && is_domain=true{fofa_excl}' if fofa_idn_parts else "",
        "master": fofa_master,
        "subdomain_spoof": _or([f'host*="{t}.*"' for t in substring_terms] + [f'host*=".{t}."' for t in substring_terms], " || ") + fofa_excl,
        "title_spoof": fofa_title + fofa_excl,
        "domain_wildcard": fofa_host + fofa_excl,
        "domain_contains": fofa_host_contains + fofa_excl,
        "cert_wildcard": fofa_cert + fofa_excl,
        "body_content": fofa_body + fofa_excl,
    }, build_fofa_search_url)

    # -------------------------------------------------------------- Censys (CenQL)
    censys_excl = _cenql_domain_exclude(legit_domains)
    censys_title = f"{cenql_any('web.endpoints.http.html_title', titles)} or {cenql_any('host.services.endpoints.http.html_title', titles)}"
    censys_names = cenql_any("web.hostname", tokens if is_multi else host_terms)
    censys_cert = cenql_any("cert.names", tokens)
    censys_dns = cenql_any("host.dns.names", host_terms)
    censys_master = censys_names if is_multi else f"({censys_title} or {censys_names} or {censys_cert} or {censys_dns}){censys_excl}"
    censys_coocc = ["(" + " and ".join(_cenql_regex_contains("web.hostname", [w]) for w in g) + ")" for g in coocc]
    censys_regex_parts = [
        _cenql_regex_contains("web.hostname", substring_terms),
        _cenql_regex_contains("cert.names", substring_terms),
        _cenql_regex_contains("host.dns.names", substring_terms),
    ] + censys_coocc
    censys_title_rx = _cenql_regex_contains("web.endpoints.http.html_title", _dedupe(titles + substring_terms))
    censys_body_rx = _cenql_regex_contains("web.endpoints.http.body", _dedupe(titles + substring_terms))
    censys_exh_parts = censys_regex_parts + [censys_title_rx, censys_body_rx]
    cloud_alt = "|".join(_re_escape(d) for d in CLOUD_ABUSE_DOMAINS[:16])
    censys_idn_parts = ([_cenql_regex_contains("web.hostname", puny_skels, prefix="xn--.*", suffix=".*")] if puny_skels else []) + [
        f'(web.hostname =~ "(?i)^xn--" and ({censys_title_rx} or {censys_body_rx}))'
    ]

    censys = _pack({
        "all_domains": f"({' or '.join(censys_regex_parts)}){censys_excl}" if censys_excl else " or ".join(censys_regex_parts),
        "exhaustive": f"({' or '.join(censys_exh_parts)}){censys_excl}" if censys_excl else " or ".join(censys_exh_parts),
        "scam_lures": (
            f"(({_cenql_regex_contains('web.hostname', substring_terms)} or {censys_title_rx} or {censys_body_rx}) "
            f'and (web.endpoints.http.html_title =~ "(?i)(login|verify|secure|kyc|support|official|account|update|wallet|claim|offer)" '
            f'or web.endpoints.http.body =~ "(?i)(password|one-time|otp|seed phrase|kyc)")){censys_excl}'
        ),
        "free_hosting": (
            f'(web.hostname =~ {cenql_quote(f"(?i)\\\\.({cloud_alt})$")} '
            f"and ({_cenql_regex_contains('web.hostname', substring_terms)} or {censys_title_rx} or {censys_body_rx}))"
        ),
        "idn_homoglyph": f"({' or '.join(censys_idn_parts)}){censys_excl}" if censys_excl else " or ".join(censys_idn_parts),
        "master": censys_master,
        "subdomain_spoof": f"{_cenql_regex_contains('web.hostname', substring_terms, prefix='(^|\\.)', suffix='\\.')}{censys_excl}",
        "title_spoof": censys_title,
        "domain_wildcard": censys_names,
        "cert_wildcard": censys_cert,
    }, build_censys_search_url)

    # ------------------------------------------------------------- URLScan
    urlscan_excl = urlscan_exclude_clause(legit_domains)
    urlscan_title = _or([f"page.title:{quote_term(t)}" for t in titles], " OR ")
    urlscan_title_tok = _or([f"page.title:{quote_term(t)}" for t in titles] + [f"page.title:{t}*" for t in substring_terms], " OR ")
    urlscan_domain = _or([f"page.domain:{t}*" for t in host_terms], " OR ")
    urlscan_domain_all = _or([f"domain:{t}*" for t in host_terms], " OR ")
    urlscan_url_prefix = _or([f"page.url:{t}*" for t in substring_terms], " OR ")
    urlscan_task_prefix = _or([f"task.url:{t}*" for t in substring_terms], " OR ")
    urlscan_file_prefix = _or([f"filename:{t}*" for t in substring_terms], " OR ")

    urlscan_domain_contains = _or([f"page.domain.keyword:*{t}*" for t in substring_terms], " OR ")
    urlscan_url_contains = _or([f"page.url:*{t}*" for t in substring_terms], " OR ")
    urlscan_task_contains = _or([f"task.url:*{t}*" for t in substring_terms], " OR ")
    urlscan_file_contains = _or([f"filename:*{t}*" for t in substring_terms], " OR ")
    urlscan_title_contains = _or([f"page.title:*{t}*" for t in substring_terms], " OR ")
    urlscan_body = _or([f"text.content:{quote_term(t)}" for t in body_titles], " OR ")

    urlscan_coocc = ["(" + " AND ".join(f"page.domain.keyword:*{w}*" for w in g) + ")" for g in coocc]
    urlscan_all_parts = [f"page.domain.keyword:*{t}*" for t in substring_terms] + [f"task.domain.keyword:*{t}*" for t in substring_terms] + urlscan_coocc
    lure_u = " OR ".join(SCAM_LURE_URL_TERMS)
    lure_t = " OR ".join(SCAM_LURE_TITLE_TERMS)
    cloud_u = " OR ".join(f"page.domain:{d}" for d in CLOUD_ABUSE_DOMAINS)
    idn_u_parts = [f"page.domain:xn--{s}*" for s in puny_skels] + [f"(page.domain:xn--* AND ({urlscan_title_tok} OR {urlscan_url_prefix}))"]
    daily = build_urlscan_daily_queries(substring_terms, titles, legit_domains, hours=24, has_key=True)

    urlscan = _pack({
        "all_domains": f"({' OR '.join(urlscan_all_parts)}){urlscan_excl}",
        "exhaustive": f"({' OR '.join(urlscan_all_parts)} OR {urlscan_url_contains} OR {urlscan_task_contains} OR {urlscan_file_contains} OR {urlscan_title_contains}){urlscan_excl}",
        "daily_domain": daily.get("domain_query", ""),
        "daily_title": daily.get("title_query", ""),
        "daily_search": daily.get("combined_query", ""),
        "scam_lures": f"(({urlscan_domain} OR {urlscan_url_prefix} OR {urlscan_task_prefix} OR {urlscan_title_tok}) AND (page.url:({lure_u}) OR page.title:({lure_t}))){urlscan_excl}",
        "free_hosting": f"(({cloud_u}) AND ({urlscan_domain} OR {urlscan_url_prefix} OR {urlscan_task_prefix} OR {urlscan_title_tok}))",
        "idn_homoglyph": f"({' OR '.join(idn_u_parts)}){urlscan_excl}",
        "master": f"({urlscan_title} OR {urlscan_domain} OR {urlscan_domain_all} OR {urlscan_url_prefix} OR {urlscan_task_prefix} OR {urlscan_file_prefix}){urlscan_excl}",
        "subdomain_spoof": _or([f"page.domain:{t}.*" for t in host_terms[:10]], " OR ") + urlscan_excl,
        "title_spoof": urlscan_title + urlscan_excl,
        "domain_wildcard": urlscan_domain + urlscan_excl,
        "domain_contains": urlscan_domain_contains + urlscan_excl,
        "url_prefix": urlscan_url_prefix + urlscan_excl,
        "body_content": urlscan_body + urlscan_excl,
    }, build_urlscan_search_url)

    # --------------------------------------------------------------- Shodan
    shodan_excl = "".join(f" -hostname:{d}" for d in legit_domains)
    shodan_cert = f"ssl.cert.subject.cn:{','.join(tokens) or primary_token}{shodan_excl}"
    shodan = _pack({
        "all_domains": f"hostname:{','.join(host_terms)}{shodan_excl}",
        "ssl_all": f"ssl:{quote_term(primary_token)}{shodan_excl}",
        "scam_lures": f'http.html:{quote_term(primary_token)} http.html:"password"{shodan_excl}',
        "master": shodan_cert,
        "subdomain_spoof": f"hostname:{','.join(f'{t}.' for t in host_terms[:8])}{shodan_excl}",
        "title_spoof": f"http.title:{quote_term(best_title)}{shodan_excl}",
        "domain_wildcard": shodan_cert,
        "cert_wildcard": shodan_cert,
        "body_content": f"http.html:{quote_term(best_title)}{shodan_excl}",
    }, build_shodan_search_url)

    return {"fofa": fofa, "censys": censys, "urlscan": urlscan, "shodan": shodan}


def _search_engine_dorks_for(terms: List[str], titles: List[str], legit_domains: List[str]) -> Dict[str, Any]:
    excl = "".join(f" -site:{d}" for d in legit_domains)
    phrase_or = _or([quote_term(t) for t in titles] + terms[:4], " OR ")
    inurl_core = _or([f"inurl:{t}" for t in terms], " OR ")
    title_core = _or([f"intitle:{quote_term(t)}" for t in titles], " OR ")

    hosting_sites = " OR ".join(f"site:{d}" for d in CLOUD_ABUSE_DOMAINS[:12])
    social_sites = " OR ".join(f"site:{d}" for d in SOCIAL[:6] + APP_STORES[:3])
    leak_sites = " OR ".join(f"site:{d}" for d in ["github.com"] + PASTE_SITES[:4])

    dork_defs = {
        "inurl": f"{inurl_core}{excl}",
        "credential_lure": f"({title_core} OR {inurl_core}) (inurl:login OR inurl:sso OR inurl:portal OR \"sign in\" OR verify OR kyc OR password OR otp){excl}",
        "wildcard_site": f"{_or([f'site:*{t}*.*' for t in terms[:6]] + [f'site:{t}.*' for t in terms[:4]], ' OR ')}{excl}",
        "free_hosting": f"({phrase_or}) ({hosting_sites})",
        "scam_campaigns": f"({phrase_or}) (\"customer care\" OR helpline OR \"toll free\" OR \"offer letter\" OR recruitment OR \"pre-launch\" OR booking OR airdrop OR giveaway){excl}",
        "social_and_apps": f"({phrase_or}) ({social_sites})",
        "leaks_and_redirects": f"({inurl_core} OR {phrase_or}) ({leak_sites} OR inurl:redirect= OR inurl:url=){excl}",
        "inurl_and_title": f"({inurl_core} OR {title_core}){excl}",
    }

    def links(q: str) -> Dict[str, str]:
        return {eng: tpl.format(urllib.parse.quote_plus(q)) for eng, tpl in ENGINES.items()}

    return {k: {"query": q, "links": links(q)} for k, q in dork_defs.items()}


def generate_keyword_dorks(keyword: str, include_variants: bool = False) -> Dict[str, Any]:
    """Generates domain-capture and cyber-scam dorks across all platforms for one keyword or domain."""
    dec = decompose_keyword(keyword, include_variants=include_variants)
    titles = dec["titles"]
    tokens = dec["tokens"]
    slugs = _dedupe(([dec["compact_slug"], dec["project_slug"]] if dec["project_slug"] else []) + dec["compound_slugs"])
    variants = dec["variants"]
    host_terms = _dedupe(tokens + slugs + variants)
    substring_terms = _substring_minimal(_dedupe(tokens + slugs + variants))
    legit = dec["legit_domain"]
    title_terms = _dedupe([t for t in tokens if len(t) >= 4] + titles)

    best_title = titles[-1] if len(titles) > 1 else titles[0]
    if dec["is_domain"] or not tokens:
        primary_token = tokens[0] if tokens else best_title.lower()
    else:
        abbrevs = {t for w in dec["raw"].split(" ") if _is_abbreviation(w) for t in _abbrev_tokens(w)}
        primary_token = next((t for t in tokens if t not in abbrevs), tokens[0])

    platforms = _build_platform_dorks(
        titles=titles, title_terms=title_terms, tokens=tokens, host_terms=host_terms,
        substring_terms=substring_terms, puny_skels=dec["punycode_skeletons"], coocc=dec["cooccurrence_groups"],
        legit_domains=[legit] if legit else [], best_title=best_title, primary_token=primary_token,
        body_titles=titles, is_multi=False,
    )

    crtsh_queries: List[Dict[str, str]] = []
    for t in substring_terms:
        crtsh_queries.append({"token": t, "query": f"%{t}%", "url": build_crtsh_search_url(t, False), "active_url": build_crtsh_search_url(t, True)})
        crtsh_queries.append({"token": f"{t}.", "query": f"{t}.%", "url": build_crtsh_search_url(f"{t}.%", False), "active_url": build_crtsh_search_url(f"{t}.%", True)})
    if dec["punycode_skeletons"]:
        sk = dec["punycode_skeletons"][0]
        crtsh_queries.append({
            "token": f"xn--*{sk}*", "query": f"xn--%{sk}%",
            "url": build_crtsh_search_url(f"xn--%{sk}%", False), "active_url": build_crtsh_search_url(f"xn--%{sk}%", True),
        })

    return {
        "keyword": keyword,
        "bare_keyword": primary_token,
        "decomposition": dec,
        **platforms,
        "crtsh": {
            "query": f"%{primary_token}%",
            "url": build_crtsh_search_url(primary_token, False),
            "active_url": build_crtsh_search_url(primary_token, True),
            "queries": crtsh_queries,
        },
        "search_engines": _search_engine_dorks_for(substring_terms, titles, [legit] if legit else []),
    }


def generate_impersonation_recon_suite(raw_input: str, include_variants: bool = False) -> Dict[str, Any]:
    """Processes multiple keywords and produces per-keyword and composite multi-keyword recon queries."""
    keywords = sanitize_keywords(raw_input)
    if not keywords:
        return {
            "total_keywords": 0, "include_variants": include_variants, "keywords": [],
            "all_tokens": [], "all_host_terms": [], "all_substring_terms": [],
            "legit_domains": [], "items": [], "master_queries": {}, "crtsh": [], "search_engines": {},
        }

    items = [generate_keyword_dorks(kw, include_variants=include_variants) for kw in keywords]
    all_tokens = _dedupe([tok for it in items for tok in it["decomposition"]["tokens"]])
    all_titles = _dedupe([t for it in items for t in it["decomposition"]["titles"]])
    all_slugs = _dedupe([
        s for it in items
        for s in (
            ([it["decomposition"]["compact_slug"], it["decomposition"]["project_slug"]] if it["decomposition"]["project_slug"] else [])
            + it["decomposition"]["compound_slugs"]
        )
    ])
    all_variants = _dedupe([v for it in items for v in it["decomposition"]["variants"]])[:30]
    all_host_terms = _dedupe(all_tokens + all_slugs + all_variants)
    all_substring_terms = _substring_minimal(_dedupe(all_tokens + all_slugs + all_variants))
    all_puny = _dedupe([s for it in items for s in it["decomposition"]["punycode_skeletons"]])[:12]
    all_coocc = [g for it in items for g in it["decomposition"]["cooccurrence_groups"]]
    legit_domains = _dedupe([it["decomposition"]["legit_domain"] for it in items if it["decomposition"]["legit_domain"]])
    title_terms = _dedupe([t for t in all_tokens if len(t) >= 4] + all_titles)
    raw_keywords = [it["keyword"] for it in items]

    platforms = _build_platform_dorks(
        titles=all_titles, title_terms=title_terms, tokens=_dedupe(all_tokens + all_variants),
        host_terms=all_host_terms, substring_terms=all_substring_terms, puny_skels=all_puny,
        coocc=all_coocc, legit_domains=legit_domains,
        best_title=all_titles[0] if all_titles else raw_keywords[0],
        primary_token=all_substring_terms[0] if all_substring_terms else raw_keywords[0].lower(),
        body_titles=raw_keywords, is_multi=True,
    )

    urlscan_excl = urlscan_exclude_clause(legit_domains)
    urlscan_title_composite = _or([f"page.title:{quote_term(t)}" for t in all_titles], " OR ")
    urlscan_domain_composite = _or([f"page.domain:{t}*" for t in all_host_terms], " OR ")
    urlscan_url_composite = _or([f"page.url:{t}*" for t in all_substring_terms], " OR ")
    urlscan_task_composite = _or([f"task.url:{t}*" for t in all_substring_terms], " OR ")
    urlscan_body_composite = _or([f"text.content:{quote_term(k)}" for k in raw_keywords], " OR ")
    has_phrases = any(not it["decomposition"]["is_domain"] and " " in it["keyword"] for it in items)
    urlscan_combined = (
        f"({urlscan_title_composite} OR {urlscan_domain_composite} OR {urlscan_url_composite} OR {urlscan_task_composite}){urlscan_excl}"
        if has_phrases else
        f"({urlscan_domain_composite} OR {urlscan_url_composite} OR {urlscan_task_composite}){urlscan_excl}"
    )

    censys_combined = cenql_any("web.hostname", all_tokens)
    shodan_excl = "".join(f" -hostname:{d}" for d in legit_domains)
    shodan_combined = f"ssl.cert.subject.cn:{','.join(_dedupe(all_tokens + all_variants))}{shodan_excl}"

    master_queries = {
        "fofa": {
            "query": platforms["fofa"]["master"], "url": platforms["fofa"]["master_url"],
            "subdomain_query": platforms["fofa"]["subdomain_spoof"], "subdomain_url": platforms["fofa"]["subdomain_spoof_url"],
            "all_domains_query": platforms["fofa"]["all_domains"], "all_domains_url": platforms["fofa"]["all_domains_url"],
            "exhaustive_query": platforms["fofa"]["exhaustive"], "exhaustive_url": platforms["fofa"]["exhaustive_url"],
            "scam_lures_query": platforms["fofa"]["scam_lures"], "scam_lures_url": platforms["fofa"]["scam_lures_url"],
            "free_hosting_query": platforms["fofa"]["free_hosting"], "free_hosting_url": platforms["fofa"]["free_hosting_url"],
            "idn_query": platforms["fofa"].get("idn_homoglyph", ""), "idn_url": platforms["fofa"].get("idn_homoglyph_url", ""),
        },
        "censys": {
            "query": censys_combined, "url": build_censys_search_url(censys_combined),
            "subdomain_query": platforms["censys"]["subdomain_spoof"], "subdomain_url": platforms["censys"]["subdomain_spoof_url"],
            "all_domains_query": platforms["censys"]["all_domains"], "all_domains_url": platforms["censys"]["all_domains_url"],
            "exhaustive_query": platforms["censys"]["exhaustive"], "exhaustive_url": platforms["censys"]["exhaustive_url"],
            "scam_lures_query": platforms["censys"]["scam_lures"], "scam_lures_url": platforms["censys"]["scam_lures_url"],
            "free_hosting_query": platforms["censys"]["free_hosting"], "free_hosting_url": platforms["censys"]["free_hosting_url"],
            "idn_query": platforms["censys"]["idn_homoglyph"], "idn_url": platforms["censys"]["idn_homoglyph_url"],
        },
        "urlscan": {
            "query": urlscan_combined, "url": build_urlscan_search_url(urlscan_combined),
            "subdomain_query": platforms["urlscan"]["subdomain_spoof"], "subdomain_url": platforms["urlscan"]["subdomain_spoof_url"],
            "all_domains_query": platforms["urlscan"]["all_domains"], "all_domains_url": platforms["urlscan"]["all_domains_url"],
            "exhaustive_query": platforms["urlscan"]["exhaustive"], "exhaustive_url": platforms["urlscan"]["exhaustive_url"],
            "daily_domain_query": platforms["urlscan"]["daily_domain"], "daily_domain_url": platforms["urlscan"]["daily_domain_url"],
            "daily_title_query": platforms["urlscan"]["daily_title"], "daily_title_url": platforms["urlscan"]["daily_title_url"],
            "daily_search_query": platforms["urlscan"]["daily_search"], "daily_search_url": platforms["urlscan"]["daily_search_url"],
            "scam_lures_query": platforms["urlscan"]["scam_lures"], "scam_lures_url": platforms["urlscan"]["scam_lures_url"],
            "free_hosting_query": platforms["urlscan"]["free_hosting"], "free_hosting_url": platforms["urlscan"]["free_hosting_url"],
            "idn_query": platforms["urlscan"]["idn_homoglyph"], "idn_url": platforms["urlscan"]["idn_homoglyph_url"],
            "title_query": urlscan_title_composite + urlscan_excl, "title_url": build_urlscan_search_url(urlscan_title_composite + urlscan_excl),
            "domain_query": urlscan_domain_composite + urlscan_excl, "domain_url": build_urlscan_search_url(urlscan_domain_composite + urlscan_excl),
            "body_query": urlscan_body_composite + urlscan_excl, "body_url": build_urlscan_search_url(urlscan_body_composite + urlscan_excl),
        },
        "shodan": {
            "query": shodan_combined, "url": build_shodan_search_url(shodan_combined),
            "subdomain_query": platforms["shodan"]["subdomain_spoof"], "subdomain_url": platforms["shodan"]["subdomain_spoof_url"],
            "hostname_query": platforms["shodan"]["all_domains"], "hostname_url": platforms["shodan"]["all_domains_url"],
            "ssl_query": platforms["shodan"]["ssl_all"], "ssl_url": platforms["shodan"]["ssl_all_url"],
            "scam_lures_query": platforms["shodan"]["scam_lures"], "scam_lures_url": platforms["shodan"]["scam_lures_url"],
        },
        "whoisxml": {
            "terms": all_substring_terms[:3],
            "exclude_domains": legit_domains,
            "spec": build_whoisxml_daily_spec(all_substring_terms, legit_domains, since_days=1, with_typos=True),
        },
    }

    crtsh_links: List[Dict[str, str]] = []
    for t in all_substring_terms:
        crtsh_links.append({"token": t, "query": f"%{t}%", "url": build_crtsh_search_url(t, False), "active_url": build_crtsh_search_url(t, True)})
        crtsh_links.append({"token": f"{t}.", "query": f"{t}.%", "url": build_crtsh_search_url(f"{t}.%", False), "active_url": build_crtsh_search_url(f"{t}.%", True)})
    if all_puny:
        crtsh_links.append({
            "token": f"xn--*{all_puny[0]}*", "query": f"xn--%{all_puny[0]}%",
            "url": build_crtsh_search_url(f"xn--%{all_puny[0]}%", False), "active_url": build_crtsh_search_url(f"xn--%{all_puny[0]}%", True),
        })

    return {
        "total_keywords": len(keywords), "include_variants": include_variants, "keywords": keywords,
        "all_tokens": all_tokens, "all_titles": all_titles, "all_host_terms": all_host_terms,
        "all_substring_terms": all_substring_terms, "all_punycode_skeletons": all_puny,
        "legit_domains": legit_domains, "items": items, "master_queries": master_queries,
        "crtsh": crtsh_links, "search_engines": _search_engine_dorks_for(all_substring_terms, all_titles, legit_domains),
    }
