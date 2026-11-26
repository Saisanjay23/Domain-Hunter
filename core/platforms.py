"""
Search-platform reference: web UI URL builders and the favicon-hash fields each
platform indexes. Keep this file as the single source of truth for syntax.

Platform notes (verified 2026-11):
- FOFA      icon_hash="<mmh3>". Boolean: && || != (). URL takes base64 query (qbase64).
            host="x" / domain="x" / cert="x" are token matches (free tier);
            substring wildcards need host*="*x*", domain*="*x*", cert*="*x*", title*="*x*"
            (paid members). Avoid status_code="200" when capturing all domains so 301/302/403/404
            and TLS-only domains are not dropped.
- Shodan    http.favicon.hash:<mmh3>. Comma-separated values are OR-ed (a,b,c);
            whitespace is AND, "-filter:value" negates. There is no OR keyword across filters.
            hostname:x searches PTR/DNS substrings; ssl:"x" searches all SSL cert data (CN+SAN);
            ssl.cert.subject.cn:x searches Subject CN. Filters require a logged-in account.
- Censys    Censys Platform / CenQL (platform.censys.io). Legacy search.censys.io is retired.
            Favicon MD5 is indexed on hosts and web properties, SHA-256 on web properties.
            ':' is a tokenized contains-match, '=' exact, field: {"a", "b"} ORs values,
            '=~ "(?i).*x.*"' runs case-insensitive regex across web.hostname / cert.names /
            host.dns.names. Use "and not (...)" for exclusions. Censys hashes only first 384 KB.
- URLScan   hash:<sha256> matches ANY HTTP response loaded during a scan (favicons, logos,
            scripts), so it also catches phishing kits that copy the brand's logo file.
            page.domain is analysed per parent-domain level (page.domain:paypal* matches
            paypal-login.com and x.paypal-verify.net, NOT secure-paypal.com).
            domain:x* searches both page.domain and task.domain; page.url:x* works anonymously
            and catches hyphenated domains like secure-paypal.com!
            Full infix/glued matching (page.domain.keyword:*x*, task.domain.keyword:*x*)
            and regex need a signed-in account; text.content (page body) is a Pro-only field.
"""

import base64
import urllib.parse

PLATFORMS = ("fofa", "shodan", "censys", "urlscan")

CENSYS_FAVICON_MD5_FIELDS = (
    "host.services.endpoints.http.favicons.hash_md5",
    "web.endpoints.http.favicons.hash_md5",
)
CENSYS_FAVICON_SHA256_FIELD = "web.endpoints.http.favicons.hash_sha256"


def build_fofa_search_url(query: str) -> str:
    """Direct FOFA result URL (query is base64 encoded)."""
    qb64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
    return f"https://fofa.info/result?qbase64={urllib.parse.quote(qb64)}"


def build_shodan_search_url(query: str) -> str:
    return f"https://www.shodan.io/search?query={urllib.parse.quote(query)}"


def build_censys_search_url(query: str) -> str:
    """Censys Platform search URL (CenQL)."""
    return f"https://platform.censys.io/search?q={urllib.parse.quote(query)}"


def build_urlscan_search_url(query: str) -> str:
    return f"https://urlscan.io/search/#{urllib.parse.quote(query)}"


def build_crtsh_search_url(pattern: str, exclude_expired: bool = False) -> str:
    """Certificate Transparency search URL (crt.sh)."""
    q = pattern if "%" in pattern else f"%{pattern}%"
    url = f"https://crt.sh/?q={urllib.parse.quote(q)}"
    return url + ("&exclude=expired" if exclude_expired else "")


def build_whoisxml_search_url(_query: str = "") -> str:
    """WhoisXML Brand Alert / Domain Discovery console."""
    return "https://brand-alert.whoisxmlapi.com/"


URL_BUILDERS = {
    "fofa": build_fofa_search_url,
    "shodan": build_shodan_search_url,
    "censys": build_censys_search_url,
    "urlscan": build_urlscan_search_url,
    "whoisxml": build_whoisxml_search_url,
}


def build_search_url(platform: str, query: str) -> str:
    builder = URL_BUILDERS.get(platform)
    return builder(query) if builder else ""


def quote_term(value: str) -> str:
    """Double-quote a value for FOFA / URLScan / Shodan query strings."""
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def urlscan_exclude_clause(allowlist) -> str:
    """Returns ' AND NOT page.apexDomain:...' excluding up to 10 own brand domains."""
    own = [d for d in (allowlist or []) if d][:10]
    if not own:
        return ""
    expr = f"({' OR '.join(own)})" if len(own) > 1 else own[0]
    return f" AND NOT page.apexDomain:{expr}"


def cenql_quote(value: str) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def cenql_any(field: str, values) -> str:
    """field: "a"  or  field: {"a", "b"}"""
    values = list(values)
    if len(values) == 1:
        return f"{field}: {cenql_quote(values[0])}"
    return f"{field}: {{{', '.join(cenql_quote(v) for v in values)}}}"
