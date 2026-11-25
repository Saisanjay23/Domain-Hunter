"""
Domain Impersonation & Brand Spoofing Dork Generator
Generates attacker-aware OSINT reconnaissance queries across FOFA, Censys, URLScan,
Shodan, Certificate Transparency (crt.sh), and Search Engines to capture every
matching domain and scam deployment vector for given keywords:

  1. All matching domains     prefix / infix / suffix / glued / hyphenated / TLS SANs
  2. Deep / compromised kits  HTML titles, cloned bodies, HTTP headers, URL paths, assets
  3. Scam & phishing lures    credential / OTP / KYC / wallet / refund / booking lures
  4. Free hosting & buckets   pages.dev, workers.dev, vercel, firebase, s3, trycloudflare...
  5. IDN / Punycode & typos   xn-- Unicode skeletons, Leet homoglyphs, hyphen splits
  6. Live multi-vector hunt   crt.sh + split URLScan + FOFA/Censys/Shodan + feeds + DNS

See core/platforms.py for the per-platform syntax notes these queries rely on.
"""

import logging
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from . import config, feeds
from .discovery import crtsh_search, resolve_domains
from .domains import looks_like_domain, normalize_host, registrable_domain, split_host
from .keypool import POOL
from .permutations import (
    UNICODE_GLYPHS,
    generate_permutations,
    homoglyph_ascii,
    omission,
    replacement,
    repetition,
    transposition,
    vowel_swap,
)
from .pivots import APP_STORES, ENGINES as SEARCH_ENGINE_URLS, FREE_HOSTING, PASTE_SITES, SOCIAL
from .platforms import (
    build_censys_search_url,
    build_crtsh_search_url,
    build_fofa_search_url,
    build_shodan_search_url,
    build_urlscan_search_url,
    cenql_any,
    cenql_quote,
)
from .sources import SEARCHERS, SourceError

logger = logging.getLogger("hunt.impersonation")

__all__ = [
    "sanitize_keywords",
    "decompose_keyword",
    "generate_keyword_dorks",
    "generate_impersonation_recon_suite",
    "capture_domains_from_keywords",
    "build_fofa_search_url",
    "build_censys_search_url",
    "build_urlscan_search_url",
    "build_shodan_search_url",
    "build_crtsh_search_url",
]

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
# 3-letter everyday English words too noisy for standalone host wildcards when paired with other words.
SHORT_NOISE_WORDS = {
    "the", "and", "for", "new", "old", "top", "big", "one", "two", "pro", "app", "web", "net",
    "buy", "get", "pay", "all", "max", "hot", "red", "sun", "air", "car", "tax", "law", "oil",
    "gas", "bio", "eco", "med", "fin", "dev", "ops", "ion", "hub", "box", "lab", "fit", "fun",
    "art", "day", "way", "run", "set", "map", "doc", "bit", "dot", "key", "tag", "use", "try",
    "see", "our", "out", "off", "now", "can", "may",
}

MIN_TOKEN_LEN = 4        # shorter tokens (co, de, gi, at) match nearly every hostname
MIN_ABBREV_TOKEN_LEN = 3  # acronyms / X&Y abbreviations such as sbi, lnt, att

_ABBREV_RE = re.compile(r"^([a-z]{1,4})&([a-z]{1,4})$", re.I)

# High-signal phishing & cyber-scam lure tokens attackers combine with brand keywords.
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
# Most frequently abused free-hosting / tunnel / cloud domains (ordered by phishing prevalence).
CLOUD_ABUSE_DOMAINS = FREE_HOSTING[:22]


def sanitize_keywords(raw_input: str) -> List[str]:
    """
    Parses keywords from comma-separated or newline-delimited strings,
    stripping URLs, schemes, quotes, and whitespace. Preserves multi-word phrases.
    """
    if not raw_input:
        return []

    tokens = re.split(r"[\r\n,;|]+", raw_input)
    cleaned = []
    seen = set()

    for t in tokens:
        item = t.strip().strip("'\"`").strip()
        if not item:
            continue

        # If user pasted a full URL, keep only the hostname
        if re.match(r"^[a-z][a-z0-9+.-]*://", item, re.I):
            try:
                parsed = urllib.parse.urlparse(item)
                item = parsed.netloc or parsed.path
            except Exception:
                pass
        elif looks_like_domain(item.split("/")[0]) and " " not in item:
            item = item.split("/")[0]

        # Email address pasted -> keep its domain
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
    """L&T, AT&T, P&G, LNT, HDFC, SBI - short all-caps or ampersand abbreviations."""
    return bool(_ABBREV_RE.match(word)) or (word.isupper() and word.isalpha() and 2 <= len(word) <= 5)


def _abbrev_tokens(word: str) -> List[str]:
    """AT&T -> att, atnt ; L&T -> lnt (lt is too short) ; HDFC -> hdfc"""
    m = _ABBREV_RE.match(word)
    if m:
        a, b = m.group(1).lower(), m.group(2).lower()
        cands = [f"{a}n{b}", f"{a}{b}"]
    else:
        cands = [word.lower()]
    return [c for c in cands if len(c) >= MIN_ABBREV_TOKEN_LEN]


def _hyphen_splits(token: str) -> List[str]:
    """pay-pal style splits for >= 6-char tokens so hyphen-evasion domains are matched."""
    t = token.lower()
    if len(t) < 6 or "-" in t or not t.isalpha():
        return []
    mid = len(t) // 2
    splits = [f"{t[:mid]}-{t[mid:]}"]
    if len(t) >= 7 and mid != 3:
        splits.append(f"{t[:3]}-{t[3:]}")
    return _dedupe(splits)


def _punycode_skeletons(tokens: List[str], limit: int = 8) -> List[str]:
    """
    Computes ASCII-stripped Punycode skeletons for IDN homoglyph hunting.
    Example: 'paypal' with Cyrillic 'а' encodes as 'xn--pypal-...' so
    'xn--pypal*' matches pаypal.com, pаypal-login.com, and pаypalverify.xyz.
    """
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
    """
    Produces high-yield attacker evasion stems (ASCII Leet homoglyphs, hyphen splits,
    transpositions, repetitions, vowel swaps, omissions, and QWERTY typos) for >= 5-char tokens.
    """
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
    """
    Drops redundant superstrings for substring (*x*) and regex (.*x.*) queries.
    Example: if 'avinya' is in terms, 'avinya-enclave' is already matched by *avinya*.
    """
    cleaned = _dedupe([t.lower() for t in terms if t])
    out: List[str] = []
    for t in cleaned:
        if any(other != t and other in t for other in cleaned):
            continue
        out.append(t)
    return out or cleaned


def decompose_keyword(raw: str, include_variants: bool = False) -> Dict[str, Any]:
    """
    Decomposes a brand keyword, project name, or domain into:
      titles              exact phrases for HTML <title> / body searches
      tokens              DNS-safe hostname tokens for host / certificate wildcards
      project_slug        hyphenated multi-word slug (avinya-enclave)
      compact_slug        joined multi-word slug (avinyaenclave)
      compound_slugs      all meaningful multi-word joined / hyphenated / underscore forms
      cooccurrence_groups word sets that must appear together when individual words are generic
      punycode_skeletons  ASCII skeletons for xn-- IDN homoglyph detection
      variants            optional high-yield typo/lookalike stems (when include_variants=True)
      legit_domain        registrable domain to EXCLUDE from results (only for domain input)
    """
    raw = re.sub(r"\s+", " ", raw.strip())
    # Normalise spaced ampersand abbreviations: "L & T" -> "L&T"
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

        # Title variant without a leading corporate abbreviation: "L&T Avinya Enclave" -> "Avinya Enclave"
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
                # Preserve a leading 3-char brand anchor (e.g. "sbi card", "tcs ion") even if lowercase
                if (
                    idx == 0
                    and len(clean) == MIN_ABBREV_TOKEN_LEN
                    and clean not in GENERIC_WORDS
                    and clean not in SHORT_NOISE_WORDS
                ):
                    anchor_toks.append(clean)

        distinctive = [w for w in word_toks if len(w) >= MIN_TOKEN_LEN and w not in GENERIC_WORDS]
        tokens = _dedupe(abbrev_toks + anchor_toks + distinctive)

        # Slugs: preserve existing project_slug / compact_slug behaviour, plus full brand+word forms.
        if len(word_toks) >= 2:
            project_slug = "-".join(word_toks)
            compact_slug = "".join(word_toks)
        elif len(full_slug_parts) >= 2:
            project_slug = "-".join(full_slug_parts)
            compact_slug = "".join(full_slug_parts)

        if len(full_slug_parts) >= 2:
            compound_slugs.extend([
                "".join(full_slug_parts),
                "-".join(full_slug_parts),
                "_".join(full_slug_parts),
            ])
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
                tokens = [w for w in word_toks if len(w) >= MIN_ABBREV_TOKEN_LEN] or [
                    re.sub(r"[^a-z0-9]", "", raw.lower())
                ]
        elif len(full_slug_parts) >= 2:
            pair_terms = [t for t in full_slug_parts if len(t) >= MIN_ABBREV_TOKEN_LEN][:3]
            if len(pair_terms) >= 2 and any(p not in tokens for p in pair_terms):
                cooccurrence_groups.append(pair_terms)

    tokens = _dedupe([t for t in tokens if t])
    compound_slugs = _dedupe([s for s in compound_slugs if s and s not in {t.lower() for t in tokens}])
    punycode_skeletons = _punycode_skeletons(tokens)
    variants = _generate_token_variants(tokens) if include_variants else []

    return {
        "raw": raw,
        "is_domain": is_domain,
        "titles": _dedupe(titles),
        "tokens": tokens,
        "project_slug": project_slug,
        "compact_slug": compact_slug,
        "compound_slugs": compound_slugs,
        "cooccurrence_groups": cooccurrence_groups,
        "punycode_skeletons": punycode_skeletons,
        "variants": variants,
        "legit_domain": legit_domain,
    }


def _or(items: List[str], sep: str) -> str:
    joined = sep.join(items)
    return f"({joined})" if len(items) > 1 else joined


def _q(value: str) -> str:
    """Double-quote a value for FOFA / URLScan / Shodan phrase matching."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _re_escape(value: str) -> str:
    """Escapes regex metacharacters for RE2 / CenQL regex literals."""
    return re.sub(r"([.+*?^$()\[\]{}|\\-])", r"\\\1", value)


def _cenql_regex_contains(field: str, terms: List[str], prefix: str = ".*", suffix: str = ".*") -> str:
    """Builds a case-insensitive CenQL regex matching any of `terms` inside `field`."""
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
    """Adds <key>_url search links for every query in the dict."""
    out: Dict[str, str] = {}
    for k, q in d.items():
        if q:
            out[k] = q
            out[f"{k}_url"] = builder(q)
    return out


def _fofa_coocc_clauses(groups: List[List[str]]) -> List[str]:
    return ["(" + " && ".join(f'host*="*{w}*"' for w in g) + ")" for g in groups]


def _urlscan_coocc_clauses(groups: List[List[str]]) -> List[str]:
    return ["(" + " AND ".join(f"page.domain.keyword:*{w}*" for w in g) + ")" for g in groups]


def _censys_coocc_clauses(groups: List[List[str]]) -> List[str]:
    return ["(" + " and ".join(_cenql_regex_contains("web.hostname", [w]) for w in g) + ")" for g in groups]


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
    """
    Shared builder producing per-keyword AND multi-keyword dorks across FOFA, Censys,
    URLScan, and Shodan without duplicating query-assembly logic.
    """
    cert_terms = _dedupe(tokens + [t for t in host_terms if t not in tokens])[:20]

    # ---------------------------------------------------------------- FOFA
    fofa_excl = "".join(f' && domain!="{d}"' for d in legit_domains)
    fofa_title = _or([f"title={_q(t)}" for t in titles], " || ")
    fofa_host = _or([f"host={_q(t)}" for t in host_terms], " || ")
    fofa_domain = _or([f"domain={_q(t)}" for t in host_terms], " || ")
    fofa_cert = _or([f"cert={_q(t)}" for t in _dedupe(tokens + [v for v in host_terms if v in substring_terms])], " || ")
    fofa_body = _or([f"body={_q(t)}" for t in titles], " || ")

    fofa_host_contains = _or([f'host*="*{t}*"' for t in substring_terms], " || ")
    fofa_title_contains = _or([f'title*="*{t}*"' for t in _dedupe(titles + substring_terms)], " || ")
    fofa_all_parts = (
        [f'domain*="*{t}*"' for t in substring_terms]
        + [f'host*="*{t}*"' for t in substring_terms]
        + [f'cert*="*{t}*"' for t in substring_terms]
        + [f'cname*="*{t}*"' for t in substring_terms]
        + _fofa_coocc_clauses(coocc)
    )
    fofa_deep_parts = fofa_all_parts + [
        f'title*="*{t}*"' for t in _dedupe(titles + substring_terms)
    ] + [
        f'body*="*{t}*"' for t in _dedupe(titles + substring_terms)
    ] + [
        f'header*="*{t}*"' for t in substring_terms
    ]

    if is_multi:
        fofa_master = f"{fofa_host} && is_domain=true{fofa_excl}"
    else:
        fofa_master = f"({fofa_title} || {fofa_host} || {fofa_domain} || {fofa_cert}) && is_domain=true{fofa_excl}"
    fofa_all_domains = f"({' || '.join(fofa_all_parts)}) && is_domain=true{fofa_excl}"
    fofa_exhaustive = f"({' || '.join(fofa_deep_parts)}) && is_domain=true{fofa_excl}"

    fofa_lure_targets = _or([f'host*="*{t}*"' for t in substring_terms] + [f'title*="*{t}*"' for t in title_terms] + [f'body*="*{t}*"' for t in title_terms], " || ")
    fofa_lure_hooks = _or(
        [f'title*="*{w}*"' for w in ("login", "verify", "secure", "kyc", "support", "official")]
        + [f'body*="*{w}*"' for w in SCAM_LURE_BODY_TERMS],
        " || ",
    )
    fofa_scam_lures = f"({fofa_lure_targets}) && ({fofa_lure_hooks}) && is_domain=true{fofa_excl}"

    fofa_cloud_hosts = _or([f'domain="{d}"' for d in CLOUD_ABUSE_DOMAINS[:15]], " || ")
    fofa_free_hosting = f"({fofa_cloud_hosts}) && ({fofa_lure_targets})"

    fofa_idn_parts = [f'host*="*{s}*"' for s in puny_skels] + [f'title*="*{t}*"' for t in title_terms] + [f'body*="*{t}*"' for t in title_terms]
    fofa_idn = f'(host*="xn--" && ({ " || ".join(fofa_idn_parts) })) && is_domain=true{fofa_excl}' if fofa_idn_parts else ""

    fofa = _pack({
        "all_domains": fofa_all_domains,
        "exhaustive": fofa_exhaustive,
        "scam_lures": fofa_scam_lures,
        "free_hosting": fofa_free_hosting,
        "idn_homoglyph": fofa_idn,
        "master": fofa_master,
        "title_spoof": fofa_title + fofa_excl,
        "domain_wildcard": fofa_host + fofa_excl,
        "domain_contains": fofa_host_contains + fofa_excl,
        "cert_wildcard": fofa_cert + fofa_excl,
        "body_content": fofa_body + fofa_excl,
    }, build_fofa_search_url)

    # -------------------------------------------------------------- Censys (CenQL)
    censys_excl = _cenql_domain_exclude(legit_domains)
    censys_title = (
        f"{cenql_any('web.endpoints.http.html_title', titles)}"
        f" or {cenql_any('host.services.endpoints.http.html_title', titles)}"
    )
    censys_names = cenql_any("web.hostname", tokens if is_multi else host_terms)
    censys_cert = cenql_any("cert.names", tokens)
    censys_dns = cenql_any("host.dns.names", host_terms)
    censys_master = censys_names if is_multi else f"({censys_title} or {censys_names} or {censys_cert} or {censys_dns}){censys_excl}"

    censys_regex_parts = [
        _cenql_regex_contains("web.hostname", substring_terms),
        _cenql_regex_contains("cert.names", substring_terms),
        _cenql_regex_contains("host.dns.names", substring_terms),
    ] + _censys_coocc_clauses(coocc)
    censys_all_domains = f"({' or '.join(censys_regex_parts)}){censys_excl}" if censys_excl else " or ".join(censys_regex_parts)

    censys_title_rx = _cenql_regex_contains("web.endpoints.http.html_title", _dedupe(titles + substring_terms))
    censys_body_rx = _cenql_regex_contains("web.endpoints.http.body", _dedupe(titles + substring_terms))
    censys_exh_parts = censys_regex_parts + [censys_title_rx, censys_body_rx]
    censys_exhaustive = f"({' or '.join(censys_exh_parts)}){censys_excl}" if censys_excl else " or ".join(censys_exh_parts)

    censys_scam_lures = (
        f"(({_cenql_regex_contains('web.hostname', substring_terms)} or {censys_title_rx} or {censys_body_rx}) "
        f'and (web.endpoints.http.html_title =~ "(?i)(login|verify|secure|kyc|support|official|account|update|wallet|claim|offer)" '
        f'or web.endpoints.http.body =~ "(?i)(password|one-time|otp|seed phrase|kyc)")){censys_excl}'
    )

    cloud_alt = "|".join(_re_escape(d) for d in CLOUD_ABUSE_DOMAINS[:16])
    censys_free_hosting = (
        f'(web.hostname =~ {cenql_quote(f"(?i)\\\\.({cloud_alt})$")} '
        f"and ({_cenql_regex_contains('web.hostname', substring_terms)} or {censys_title_rx} or {censys_body_rx}))"
    )

    censys_idn_parts = []
    if puny_skels:
        censys_idn_parts.append(_cenql_regex_contains("web.hostname", puny_skels, prefix="xn--.*", suffix=".*"))
    censys_idn_parts.append(f'(web.hostname =~ "(?i)^xn--" and ({censys_title_rx} or {censys_body_rx}))')
    censys_idn = f"({' or '.join(censys_idn_parts)}){censys_excl}" if censys_excl else " or ".join(censys_idn_parts)

    censys = _pack({
        "all_domains": censys_all_domains,
        "exhaustive": censys_exhaustive,
        "scam_lures": censys_scam_lures,
        "free_hosting": censys_free_hosting,
        "idn_homoglyph": censys_idn,
        "master": censys_master,
        "title_spoof": censys_title,
        "domain_wildcard": censys_names,
        "cert_wildcard": censys_cert,
    }, build_censys_search_url)

    # ------------------------------------------------------------- URLScan
    urlscan_excl = ""
    if legit_domains:
        urlscan_excl = " AND NOT page.apexDomain:" + _or(legit_domains, " OR ")

    urlscan_title = _or([f"page.title:{_q(t)}" for t in titles], " OR ")
    urlscan_title_tok = _or([f"page.title:{_q(t)}" for t in titles] + [f"page.title:{t}*" for t in substring_terms], " OR ")
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
    urlscan_body = _or([f"text.content:{_q(t)}" for t in body_titles], " OR ")

    urlscan_master = f"({urlscan_title} OR {urlscan_domain} OR {urlscan_domain_all} OR {urlscan_url_prefix} OR {urlscan_task_prefix} OR {urlscan_file_prefix}){urlscan_excl}"

    urlscan_all_parts = (
        [f"page.domain.keyword:*{t}*" for t in substring_terms]
        + [f"task.domain.keyword:*{t}*" for t in substring_terms]
        + _urlscan_coocc_clauses(coocc)
    )
    urlscan_all_domains = f"({' OR '.join(urlscan_all_parts)}){urlscan_excl}"
    urlscan_exhaustive = (
        f"({' OR '.join(urlscan_all_parts)} OR {urlscan_url_contains} OR {urlscan_task_contains} "
        f"OR {urlscan_file_contains} OR {urlscan_title_contains}){urlscan_excl}"
    )

    lure_u = " OR ".join(SCAM_LURE_URL_TERMS)
    lure_t = " OR ".join(SCAM_LURE_TITLE_TERMS)
    urlscan_scam_lures = (
        f"(({urlscan_domain} OR {urlscan_url_prefix} OR {urlscan_task_prefix} OR {urlscan_title_tok}) "
        f"AND (page.url:({lure_u}) OR page.title:({lure_t}))){urlscan_excl}"
    )

    cloud_u = " OR ".join(f"page.domain:{d}" for d in CLOUD_ABUSE_DOMAINS)
    urlscan_free_hosting = f"(({cloud_u}) AND ({urlscan_domain} OR {urlscan_url_prefix} OR {urlscan_task_prefix} OR {urlscan_title_tok}))"

    idn_u_parts = [f"page.domain:xn--{s}*" for s in puny_skels]
    idn_u_parts.append(f"(page.domain:xn--* AND ({urlscan_title_tok} OR {urlscan_url_prefix}))")
    urlscan_idn = f"({' OR '.join(idn_u_parts)}){urlscan_excl}"

    urlscan = _pack({
        "all_domains": urlscan_all_domains,
        "exhaustive": urlscan_exhaustive,
        "scam_lures": urlscan_scam_lures,
        "free_hosting": urlscan_free_hosting,
        "idn_homoglyph": urlscan_idn,
        "master": urlscan_master,
        "title_spoof": urlscan_title + urlscan_excl,
        "domain_wildcard": urlscan_domain + urlscan_excl,
        "domain_contains": urlscan_domain_contains + urlscan_excl,
        "url_prefix": urlscan_url_prefix + urlscan_excl,
        "body_content": urlscan_body + urlscan_excl,
    }, build_urlscan_search_url)

    # --------------------------------------------------------------- Shodan
    # No OR keyword across filters; whitespace is AND; comma-separated values within a filter are OR-ed.
    shodan_excl = "".join(f" -hostname:{d}" for d in legit_domains)
    shodan_cert_terms = _dedupe(tokens + [t for t in host_terms if t not in tokens and len(t) >= 4 and "_" not in t])
    # Keep test_impersonation cert_wildcard exact for tokens
    shodan_cert = f"ssl.cert.subject.cn:{','.join(tokens) or primary_token}{shodan_excl}"
    shodan_host = f"hostname:{','.join(host_terms)}{shodan_excl}"
    shodan_ssl_all = f"ssl:{_q(primary_token)}{shodan_excl}"
    shodan_title = f"http.title:{_q(best_title)}{shodan_excl}"
    shodan_body = f"http.html:{_q(best_title)}{shodan_excl}"
    shodan_scam_lures = f'http.html:{_q(primary_token)} http.html:"password"{shodan_excl}'

    shodan = _pack({
        "all_domains": shodan_host,
        "ssl_all": shodan_ssl_all,
        "scam_lures": shodan_scam_lures,
        "master": shodan_cert,
        "title_spoof": shodan_title,
        "domain_wildcard": shodan_cert,
        "cert_wildcard": shodan_cert,
        "body_content": shodan_body,
    }, build_shodan_search_url)
    # Silence unused lint if cert_terms only used later
    _ = cert_terms, shodan_cert_terms

    return {"fofa": fofa, "censys": censys, "urlscan": urlscan, "shodan": shodan}


def _search_engine_dorks_for(terms: List[str], titles: List[str], legit_domains: List[str]) -> Dict[str, Any]:
    """Builds attacker-centric Google / Bing / DuckDuckGo / Yandex domain-capture dork packs."""
    excl = "".join(f" -site:{d}" for d in legit_domains)
    phrase_or = _or([_q(t) for t in titles] + terms[:4], " OR ")
    inurl_core = _or([f"inurl:{t}" for t in terms], " OR ")
    title_core = _or([f"intitle:{_q(t)}" for t in titles], " OR ")

    hosting_sites = " OR ".join(f"site:{d}" for d in CLOUD_ABUSE_DOMAINS[:12])
    social_sites = " OR ".join(f"site:{d}" for d in SOCIAL[:6] + APP_STORES[:3])
    leak_sites = " OR ".join(f"site:{d}" for d in ["github.com"] + PASTE_SITES[:4])

    dork_defs = {
        "inurl": f"{inurl_core}{excl}",
        "credential_lure": f"({title_core} OR {inurl_core}) (login OR \"sign in\" OR verify OR kyc OR password OR otp OR wallet OR claim OR refund){excl}",
        "wildcard_site": f"{_or([f'site:*{t}*.*' for t in terms[:6]], ' OR ')}{excl}",
        "free_hosting": f"({phrase_or}) ({hosting_sites})",
        "scam_campaigns": f"({phrase_or}) (\"customer care\" OR helpline OR \"toll free\" OR \"offer letter\" OR recruitment OR \"pre-launch\" OR booking OR airdrop OR giveaway){excl}",
        "social_and_apps": f"({phrase_or}) ({social_sites})",
        "leaks_and_redirects": f"({inurl_core} OR {phrase_or}) ({leak_sites} OR inurl:redirect= OR inurl:url=){excl}",
        # Keep backward-compat key too
        "inurl_and_title": f"({inurl_core} OR {title_core}){excl}",
    }

    def links(q: str) -> Dict[str, str]:
        return {eng: tpl.format(urllib.parse.quote_plus(q)) for eng, tpl in SEARCH_ENGINE_URLS.items()}

    return {k: {"query": q, "links": links(q)} for k, q in dork_defs.items()}


def generate_keyword_dorks(keyword: str, include_variants: bool = False) -> Dict[str, Any]:
    """
    Generates exhaustive domain-capture and cyber-scam dorks across FOFA, Censys,
    URLScan, Shodan, crt.sh, and Search Engines for a keyword, project name, brand
    term, or root domain.
    """
    dec = decompose_keyword(keyword, include_variants=include_variants)
    titles = dec["titles"]
    tokens = dec["tokens"]
    slugs = _dedupe(
        ([dec["compact_slug"], dec["project_slug"]] if dec["project_slug"] else [])
        + dec["compound_slugs"]
    )
    variants = dec["variants"]
    coocc = dec["cooccurrence_groups"]
    puny_skels = dec["punycode_skeletons"]

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
        titles=titles,
        title_terms=title_terms,
        tokens=tokens,
        host_terms=host_terms,
        substring_terms=substring_terms,
        puny_skels=puny_skels,
        coocc=coocc,
        legit_domains=[legit] if legit else [],
        best_title=best_title,
        primary_token=primary_token,
        body_titles=titles,
        is_multi=False,
    )

    crtsh_queries = [
        {
            "token": t,
            "query": f"%{t}%",
            "url": build_crtsh_search_url(t, exclude_expired=False),
            "active_url": build_crtsh_search_url(t, exclude_expired=True),
        }
        for t in substring_terms
    ]
    if puny_skels:
        crtsh_queries.append({
            "token": f"xn--*{puny_skels[0]}*",
            "query": f"xn--%{puny_skels[0]}%",
            "url": build_crtsh_search_url(f"xn--%{puny_skels[0]}%", exclude_expired=False),
            "active_url": build_crtsh_search_url(f"xn--%{puny_skels[0]}%", exclude_expired=True),
        })

    crtsh = {
        "query": f"%{primary_token}%",
        "url": build_crtsh_search_url(primary_token, exclude_expired=False),
        "active_url": build_crtsh_search_url(primary_token, exclude_expired=True),
        "queries": crtsh_queries,
    }
    search_engines = _search_engine_dorks_for(
        substring_terms, titles, [legit] if legit else []
    )

    return {
        "keyword": keyword,
        "bare_keyword": primary_token,
        "decomposition": dec,
        **platforms,
        "crtsh": crtsh,
        "search_engines": search_engines,
    }


def generate_impersonation_recon_suite(raw_input: str, include_variants: bool = False) -> Dict[str, Any]:
    """
    Processes multiple keywords and produces per-keyword dorks as well as
    multi-keyword composite master, all-domain, scam-lure, free-hosting,
    and IDN homoglyph queries for FOFA, Censys, URLScan, Shodan, crt.sh,
    and Search Engines.
    """
    keywords = sanitize_keywords(raw_input)
    if not keywords:
        return {
            "total_keywords": 0,
            "include_variants": include_variants,
            "keywords": [],
            "all_tokens": [],
            "all_host_terms": [],
            "all_substring_terms": [],
            "legit_domains": [],
            "items": [],
            "master_queries": {},
            "crtsh": [],
            "search_engines": {},
        }

    items = [generate_keyword_dorks(kw, include_variants=include_variants) for kw in keywords]

    all_tokens = _dedupe([tok for it in items for tok in it["decomposition"]["tokens"]])
    all_titles = _dedupe([t for it in items for t in it["decomposition"]["titles"]])
    all_slugs = _dedupe([
        s for it in items
        for s in (
            ([it["decomposition"]["compact_slug"], it["decomposition"]["project_slug"]]
             if it["decomposition"]["project_slug"] else [])
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
        titles=all_titles,
        title_terms=title_terms,
        tokens=_dedupe(all_tokens + all_variants),
        host_terms=all_host_terms,
        substring_terms=all_substring_terms,
        puny_skels=all_puny,
        coocc=all_coocc,
        legit_domains=legit_domains,
        best_title=all_titles[0] if all_titles else raw_keywords[0],
        primary_token=all_substring_terms[0] if all_substring_terms else raw_keywords[0].lower(),
        body_titles=raw_keywords,
        is_multi=True,
    )

    # Preserve exact composite URLScan master rule when no multi-word phrases
    urlscan_excl = (" AND NOT page.apexDomain:" + _or(legit_domains, " OR ")) if legit_domains else ""
    urlscan_title_composite = _or([f"page.title:{_q(t)}" for t in all_titles], " OR ")
    urlscan_domain_composite = _or([f"page.domain:{t}*" for t in all_host_terms], " OR ")
    urlscan_url_composite = _or([f"page.url:{t}*" for t in all_substring_terms], " OR ")
    urlscan_task_composite = _or([f"task.url:{t}*" for t in all_substring_terms], " OR ")
    urlscan_body_composite = _or([f"text.content:{_q(k)}" for k in raw_keywords], " OR ")
    has_phrases = any(not it["decomposition"]["is_domain"] and " " in it["keyword"] for it in items)
    if has_phrases:
        urlscan_combined = f"({urlscan_title_composite} OR {urlscan_domain_composite} OR {urlscan_url_composite} OR {urlscan_task_composite}){urlscan_excl}"
    else:
        urlscan_combined = f"({urlscan_domain_composite} OR {urlscan_url_composite} OR {urlscan_task_composite}){urlscan_excl}"

    # Censys combined tokenized preserves clean test expectation web.hostname: {...}
    censys_combined = cenql_any("web.hostname", all_tokens)
    shodan_excl = "".join(f" -hostname:{d}" for d in legit_domains)
    shodan_combined = f"ssl.cert.subject.cn:{','.join(_dedupe(all_tokens + all_variants))}{shodan_excl}"

    master_queries = {
        "fofa": {
            "query": platforms["fofa"]["master"],
            "url": platforms["fofa"]["master_url"],
            "all_domains_query": platforms["fofa"]["all_domains"],
            "all_domains_url": platforms["fofa"]["all_domains_url"],
            "exhaustive_query": platforms["fofa"]["exhaustive"],
            "exhaustive_url": platforms["fofa"]["exhaustive_url"],
            "scam_lures_query": platforms["fofa"]["scam_lures"],
            "scam_lures_url": platforms["fofa"]["scam_lures_url"],
            "free_hosting_query": platforms["fofa"]["free_hosting"],
            "free_hosting_url": platforms["fofa"]["free_hosting_url"],
            "idn_query": platforms["fofa"].get("idn_homoglyph", ""),
            "idn_url": platforms["fofa"].get("idn_homoglyph_url", ""),
        },
        "censys": {
            "query": censys_combined,
            "url": build_censys_search_url(censys_combined),
            "all_domains_query": platforms["censys"]["all_domains"],
            "all_domains_url": platforms["censys"]["all_domains_url"],
            "exhaustive_query": platforms["censys"]["exhaustive"],
            "exhaustive_url": platforms["censys"]["exhaustive_url"],
            "scam_lures_query": platforms["censys"]["scam_lures"],
            "scam_lures_url": platforms["censys"]["scam_lures_url"],
            "free_hosting_query": platforms["censys"]["free_hosting"],
            "free_hosting_url": platforms["censys"]["free_hosting_url"],
            "idn_query": platforms["censys"]["idn_homoglyph"],
            "idn_url": platforms["censys"]["idn_homoglyph_url"],
        },
        "urlscan": {
            "query": urlscan_combined,
            "url": build_urlscan_search_url(urlscan_combined),
            "all_domains_query": platforms["urlscan"]["all_domains"],
            "all_domains_url": platforms["urlscan"]["all_domains_url"],
            "exhaustive_query": platforms["urlscan"]["exhaustive"],
            "exhaustive_url": platforms["urlscan"]["exhaustive_url"],
            "scam_lures_query": platforms["urlscan"]["scam_lures"],
            "scam_lures_url": platforms["urlscan"]["scam_lures_url"],
            "free_hosting_query": platforms["urlscan"]["free_hosting"],
            "free_hosting_url": platforms["urlscan"]["free_hosting_url"],
            "idn_query": platforms["urlscan"]["idn_homoglyph"],
            "idn_url": platforms["urlscan"]["idn_homoglyph_url"],
            "title_query": urlscan_title_composite + urlscan_excl,
            "title_url": build_urlscan_search_url(urlscan_title_composite + urlscan_excl),
            "domain_query": urlscan_domain_composite + urlscan_excl,
            "domain_url": build_urlscan_search_url(urlscan_domain_composite + urlscan_excl),
            "body_query": urlscan_body_composite + urlscan_excl,
            "body_url": build_urlscan_search_url(urlscan_body_composite + urlscan_excl),
        },
        "shodan": {
            "query": shodan_combined,
            "url": build_shodan_search_url(shodan_combined),
            "hostname_query": platforms["shodan"]["all_domains"],
            "hostname_url": platforms["shodan"]["all_domains_url"],
            "ssl_query": platforms["shodan"]["ssl_all"],
            "ssl_url": platforms["shodan"]["ssl_all_url"],
            "scam_lures_query": platforms["shodan"]["scam_lures"],
            "scam_lures_url": platforms["shodan"]["scam_lures_url"],
        },
    }

    crtsh_links = [
        {
            "token": t,
            "query": f"%{t}%",
            "url": build_crtsh_search_url(t, exclude_expired=False),
            "active_url": build_crtsh_search_url(t, exclude_expired=True),
        }
        for t in all_substring_terms
    ]
    if all_puny:
        crtsh_links.append({
            "token": f"xn--*{all_puny[0]}*",
            "query": f"xn--%{all_puny[0]}%",
            "url": build_crtsh_search_url(f"xn--%{all_puny[0]}%", exclude_expired=False),
            "active_url": build_crtsh_search_url(f"xn--%{all_puny[0]}%", exclude_expired=True),
        })
    search_engines = _search_engine_dorks_for(all_substring_terms, all_titles, legit_domains)

    return {
        "total_keywords": len(keywords),
        "include_variants": include_variants,
        "keywords": keywords,
        "all_tokens": all_tokens,
        "all_host_terms": all_host_terms,
        "all_substring_terms": all_substring_terms,
        "all_punycode_skeletons": all_puny,
        "legit_domains": legit_domains,
        "items": items,
        "master_queries": master_queries,
        "crtsh": crtsh_links,
        "search_engines": search_engines,
    }


def _host_matches_terms(host: str, terms: List[str], coocc: List[List[str]], puny_skels: Optional[List[str]] = None) -> bool:
    """Checks whether a captured hostname matches the keyword terms, co-occurrence group, or IDN skeleton."""
    h = host.lower()
    flat = h.replace("-", "")
    for t in terms:
        tl = t.lower()
        if tl in h or tl.replace("-", "") in flat:
            return True
    for g in coocc:
        if all(w.lower() in h for w in g):
            return True
    if puny_skels and "xn--" in h:
        if any(sk.lower() in h for sk in puny_skels):
            return True
    return False


def capture_domains_from_keywords(
    raw_input: str,
    include_variants: bool = False,
    use_ct: bool = True,
    use_intel: bool = True,
    use_feeds: bool = True,
    use_dns: bool = False,
    max_ct_tokens: int = 4,
) -> Dict[str, Any]:
    """
    Executes multi-vector dorks across Certificate Transparency (crt.sh),
    URLScan (domains, URLs/assets, free hosting, IDN punycode), configured
    threat-intel platforms (FOFA, Censys, Shodan), phishing feeds, and optional
    live DNS lookalike resolution to capture every matching domain.
    """
    suite = generate_impersonation_recon_suite(raw_input, include_variants=include_variants)
    if not suite["total_keywords"]:
        return {
            "total_keywords": 0,
            "total_domains": 0,
            "total_apex_domains": 0,
            "domains": [],
            "apex_domains": [],
            "source_status": [],
            "suite": suite,
        }

    legit = set(suite["legit_domains"])
    terms = suite["all_substring_terms"]
    puny_skels = suite.get("all_punycode_skeletons") or []
    coocc = [g for it in suite["items"] for g in it["decomposition"]["cooccurrence_groups"]]
    mq = suite["master_queries"]

    captured: Dict[str, Dict[str, Any]] = {}
    status: List[Dict[str, Any]] = []

    def record_host(host: Optional[str], source: str, title: str = "", url: Optional[str] = None,
                    ip: Optional[str] = None, time_str: str = "") -> bool:
        if not host:
            return False
        h = normalize_host(host).lstrip("*.")
        if not h or "." not in h or " " in h:
            return False
        apex = registrable_domain(h) or h
        if apex in legit or h in legit:
            return False
        entry = captured.get(h)
        if entry is None:
            entry = captured[h] = {
                "domain": h,
                "apex_domain": apex,
                "sources": [],
                "title": "",
                "url": None,
                "ip": None,
                "last_seen": "",
            }
        if source not in entry["sources"]:
            entry["sources"].append(source)
        if title and not entry["title"]:
            entry["title"] = title[:160]
        if url and not entry["url"]:
            entry["url"] = url
        if ip and not entry["ip"]:
            entry["ip"] = ip
        if time_str and time_str > entry["last_seen"]:
            entry["last_seen"] = time_str
        return True

    tasks: List[Tuple[str, str, Any]] = []

    if use_ct:
        ct_terms = [t for t in terms if len(t) >= MIN_ABBREV_TOKEN_LEN][:max_ct_tokens]
        for tok in ct_terms:
            tasks.append(("crt.sh", f"%{tok}%", lambda t=tok: ("ct", crtsh_search(t, timeout=30, retries=2))))

    if use_intel:
        # Multi-vector URLScan capture so a 100-result cap on one view doesn't hide kits on others.
        has_urlscan_key = bool(config.get("URLSCAN_API_KEY"))
        us_size = 500 if has_urlscan_key else 100
        us_dom_q = mq["urlscan"]["all_domains_query"] if has_urlscan_key else mq["urlscan"]["domain_query"]
        us_excl = (" AND NOT page.apexDomain:" + _or(list(legit), " OR ")) if legit else ""
        us_url_q = (
            "("
            + _or([f"page.url:{t}*" for t in terms], " OR ")
            + " OR "
            + _or([f"task.url:{t}*" for t in terms], " OR ")
            + " OR "
            + _or([f"filename:{t}*" for t in terms], " OR ")
            + ")"
            + us_excl
        )
        tasks.append(("URLScan (Domains)", us_dom_q, lambda q=us_dom_q: ("hits", SEARCHERS["urlscan"](q, size=us_size))))
        tasks.append(("URLScan (URLs & Kits)", us_url_q, lambda q=us_url_q: ("hits", SEARCHERS["urlscan"](q, size=us_size))))
        tasks.append(("URLScan (Free Hosting)", mq["urlscan"]["free_hosting_query"], lambda q=mq["urlscan"]["free_hosting_query"]: ("hits", SEARCHERS["urlscan"](q, size=us_size))))
        tasks.append(("URLScan (IDN Punycode)", mq["urlscan"]["idn_query"], lambda q=mq["urlscan"]["idn_query"]: ("hits", SEARCHERS["urlscan"](q, size=us_size))))

        def _is_plan_forbidden(err: SourceError) -> bool:
            msg = str(err).lower()
            return err.kind == "forbidden" or "does not allow" in msg or "forbidden" in msg

        if config.is_configured("fofa"):
            def run_fofa():
                try:
                    return ("hits", SEARCHERS["fofa"](mq["fofa"]["exhaustive_query"], size=500))
                except SourceError as e:
                    if _is_plan_forbidden(e):
                        POOL.reset("fofa")
                        return ("hits", SEARCHERS["fofa"](mq["fofa"]["query"], size=500))
                    raise
            tasks.append(("FOFA", mq["fofa"]["exhaustive_query"], run_fofa))

        if config.is_configured("censys"):
            def run_censys():
                try:
                    return ("hits", SEARCHERS["censys"](mq["censys"]["exhaustive_query"], size=100))
                except SourceError as e:
                    if _is_plan_forbidden(e):
                        POOL.reset("censys")
                        return ("hits", SEARCHERS["censys"](mq["censys"]["query"], size=100))
                    raise
            tasks.append(("Censys", mq["censys"]["exhaustive_query"], run_censys))

        if config.is_configured("shodan"):
            tasks.append(("Shodan (Cert CN)", mq["shodan"]["query"], lambda q=mq["shodan"]["query"]: ("hits", SEARCHERS["shodan"](q, size=100))))
            tasks.append(("Shodan (Hostname)", mq["shodan"]["hostname_query"], lambda q=mq["shodan"]["hostname_query"]: ("hits", SEARCHERS["shodan"](q, size=100))))
    else:
        status.append({"source": "URLScan", "query": "", "count": 0, "error": "disabled", "ran": False})

    for src_id, name in (("fofa", "FOFA"), ("censys", "Censys"), ("shodan", "Shodan")):
        if use_intel and not config.is_configured(src_id):
            status.append({"source": name, "query": "", "count": 0, "error": "no API key configured", "ran": False})

    if use_feeds:
        feed_tokens = [t for t in terms if len(t) >= MIN_ABBREV_TOKEN_LEN]
        tasks.append(("Phishing feeds", ", ".join(feed_tokens), lambda ft=feed_tokens: ("feed", feeds.match(ft, list(legit)))))

    if use_dns:
        def run_dns_probe():
            seed_domains = [it["decomposition"]["legit_domain"] for it in suite["items"] if it["decomposition"]["legit_domain"]]
            if not seed_domains:
                seed_domains = [f"{t}.com" for t in suite["all_tokens"][:2] if len(t) >= 4 and "-" not in t]
            cand_names = list(seed_domains)
            for sd in seed_domains[:2]:
                cand_names.extend(p["domain"] for p in generate_permutations(sd, depth="quick", max_results=220))
            resolved = resolve_domains(cand_names[:350], concurrency=120, timeout=1.5)
            return ("dns", [info for info in resolved.values() if info.get("registered")])

        tasks.append(("Live DNS lookalikes", ", ".join(suite["all_tokens"][:2]), run_dns_probe))

    with ThreadPoolExecutor(max_workers=6) as pool:
        futs = {pool.submit(fn): (src, q) for src, q, fn in tasks}
        for fut in as_completed(futs):
            src, q = futs[fut]
            rec = {"source": src, "query": q, "count": 0, "error": None, "ran": True}
            try:
                kind, payload = fut.result()
                added = 0
                if kind == "ct":
                    if payload.get("error"):
                        rec["error"] = payload["error"]
                    for host, meta in (payload.get("hosts") or {}).items():
                        if _host_matches_terms(host, terms, coocc, puny_skels):
                            if record_host(host, "crt.sh", time_str=meta.get("last_seen", "")):
                                added += 1
                elif kind == "feed":
                    if payload.get("errors"):
                        rec["error"] = "; ".join(payload["errors"])
                    for h in payload.get("hits") or []:
                        if record_host(h.get("host"), h.get("feed_name") or "feed", url=h.get("url")):
                            added += 1
                elif kind == "dns":
                    for info in payload or []:
                        ips = info.get("a") or info.get("aaaa") or []
                        if record_host(info.get("domain"), "dns-probe", ip=ips[0] if ips else None):
                            added += 1
                elif kind == "hits":
                    tag = "urlscan" if src.startswith("URLScan") else src.split(" ")[0].lower()
                    for h in payload or []:
                        if record_host(
                            h.get("host"),
                            tag,
                            title=h.get("title", ""),
                            url=h.get("url"),
                            ip=h.get("ip"),
                            time_str=h.get("time", ""),
                        ):
                            added += 1
                rec["count"] = added
            except SourceError as e:
                rec["error"] = str(e)
            except Exception as e:
                rec["error"] = str(e)
            status.append(rec)

    domains = sorted(
        captured.values(),
        key=lambda d: (-len(d["sources"]), -(1 if _host_matches_terms(d["domain"], terms, coocc, puny_skels) else 0), d["domain"]),
    )
    apex_domains = list(dict.fromkeys(d["apex_domain"] for d in domains))

    return {
        "total_keywords": suite["total_keywords"],
        "total_domains": len(domains),
        "total_apex_domains": len(apex_domains),
        "domains": domains,
        "apex_domains": apex_domains,
        "source_status": status,
        "suite": suite,
    }
