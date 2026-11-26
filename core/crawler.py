import base64
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin, urlunparse, unquote_to_bytes
import urllib3
import requests
from bs4 import BeautifulSoup

from .hasher import analyze_icon_bytes, is_image_bytes
from .domains import normalize_host, registrable_domain, same_organization
from .netguard import PublicOnlyAdapter

# Suppress InsecureRequestWarning when fallback is triggered
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

MAX_HTML_BYTES = 3 * 1024 * 1024
MAX_ASSET_BYTES = 5 * 1024 * 1024
MAX_LOGO_CANDIDATES = 6
MAX_IMG_LOGOS = 3

ANALYTICS_RE = re.compile(r"\b(UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{8,12}|GTM-[A-Z0-9]{5,9}|AW-\d{8,12})\b")
ICON_REL_TOKENS = {"icon", "apple-touch-icon", "apple-touch-icon-precomposed", "mask-icon", "fluid-icon"}
SMALL_ICON_SIZES = ("16x16", "32x32", "48x48")

logger = logging.getLogger("favicon_crawler")


@dataclass
class FetchResult:
    url: str                 # final URL after redirects
    status: int
    headers: Dict[str, str]
    content: bytes
    history: List[str] = field(default_factory=list)

    @property
    def content_type(self) -> str:
        return (self.headers.get("content-type") or "").lower()

    def looks_like_html(self) -> bool:
        head = self.content[:1024].lstrip().lower()
        return "html" in self.content_type or head.startswith((b"<!doctype html", b"<html", b"<head", b"<meta"))


def decode_data_uri(uri: str) -> Optional[bytes]:
    """Decodes a data: URI (base64 or percent-encoded). Returns None if malformed/empty."""
    try:
        header, _, payload = uri.partition(",")
        if not header.lower().startswith("data:"):
            return None
        data = base64.b64decode(payload + "=" * (-len(payload) % 4)) if ";base64" in header.lower() else unquote_to_bytes(payload)
        return data or None
    except Exception:
        return None


def _rel_tokens(link) -> Set[str]:
    rel = link.get("rel")
    if isinstance(rel, str):
        rel = rel.split()
    return {r.strip().lower() for r in (rel or []) if r and r.strip()}


class FaviconCrawler:
    """
    Crawls a domain/URL to discover, download, and analyze all favicon and icon variations.
    """

    def __init__(
        self,
        timeout: int = 10,
        user_agent: str = DEFAULT_USER_AGENT,
        verify_ssl: bool = True,
        include_logos: bool = False,
        probe_subdomains: bool = False,
        max_workers: int = 8,
    ):
        self.timeout = timeout
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl
        self.include_logos = include_logos
        self.probe_subdomains = probe_subdomains
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent, **DEFAULT_HEADERS})
        # PublicOnlyAdapter: never connect to loopback / private / link-local addresses (SSRF via lookalike DNS or redirects)
        adapter = PublicOnlyAdapter(pool_connections=max_workers * 2, pool_maxsize=max_workers * 2)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    # ------------------------------------------------------------------ HTTP
    def _request(self, url: str, verify: bool, max_bytes: int) -> FetchResult:
        with self.session.get(
            url, timeout=self.timeout, verify=verify, allow_redirects=True, stream=True
        ) as resp:
            chunks, total = [], 0
            for chunk in resp.iter_content(chunk_size=65536):
                chunks.append(chunk)
                total += len(chunk)
                if total >= max_bytes:
                    break
            return FetchResult(
                url=resp.url,
                status=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()},
                content=b"".join(chunks)[:max_bytes],
                history=[r.url for r in resp.history],
            )

    def _safe_get(self, url: str, max_bytes: int = MAX_ASSET_BYTES) -> Optional[FetchResult]:
        """
        GET with size cap, timeout, and a retry without certificate verification
        (many phishing / internal hosts use self-signed or mismatched certificates).
        """
        if not url.lower().startswith(("http://", "https://")):
            return None
        try:
            return self._request(url, self.verify_ssl, max_bytes)
        except requests.exceptions.SSLError:
            if not self.verify_ssl:
                return None
            try:
                return self._request(url, False, max_bytes)
            except Exception as e:
                logger.debug(f"Failed to fetch {url} without SSL verification: {e}")
                return None
        except Exception as e:
            logger.debug(f"Failed to fetch {url}: {e}")
            return None

    # ------------------------------------------------------------ Homepage
    def normalize_target(self, target: str) -> Tuple[str, str]:
        """
        Normalizes input target (e.g. 'gi-de.com', 'HTTP://Example.com/sub', ' "bbc.co.uk/" ')
        Returns (domain, base_url). Hostnames are lowercased and IDN-encoded.
        """
        target = target.strip().strip("'\"`<>").strip()
        if not re.match(r"^https?://", target, re.IGNORECASE):
            target = "https://" + target.lstrip("/")
        parsed = urlparse(target)
        host = normalize_host(parsed.netloc)
        netloc = f"{host}:{parsed.port}" if parsed.port and parsed.port not in (80, 443) else host
        url = urlunparse((parsed.scheme.lower(), netloc, parsed.path or "/", "", parsed.query, ""))
        return netloc, url

    def _homepage_variants(self, initial_url: str) -> List[str]:
        """https -> https://www. (for apex domains) -> http -> http://www."""
        parsed = urlparse(initial_url)
        host = parsed.hostname or ""
        hosts = [parsed.netloc]
        if not host.startswith("www.") and registrable_domain(host) == host:
            hosts.append("www." + parsed.netloc)
        schemes = [parsed.scheme] + (["http"] if parsed.scheme == "https" else [])
        variants = []
        for scheme in schemes:
            for h in hosts:
                u = urlunparse((scheme, h, parsed.path or "/", "", parsed.query, ""))
                if u not in variants:
                    variants.append(u)
        return variants

    @staticmethod
    def _parse_html(res: FetchResult) -> BeautifulSoup:
        encoding = None
        m = re.search(r"charset=([\w\-]+)", res.content_type)
        if m:
            encoding = m.group(1)
        return BeautifulSoup(res.content, "html.parser", from_encoding=encoding)

    @staticmethod
    def _meta_refresh_target(soup: BeautifulSoup, base_url: str) -> Optional[str]:
        meta = soup.find("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)})
        if not meta:
            return None
        m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", meta.get("content") or "", re.I)
        return urljoin(base_url, m.group(1).strip()) if m else None

    def fetch_homepage(self, initial_url: str) -> Tuple[Optional[BeautifulSoup], str]:
        """
        Fetches the target homepage, trying https, www., and http variants and following
        one level of <meta http-equiv="refresh"> redirects.
        Returns (parsed_html_or_None, final_url).
        """
        error_page: Optional[FetchResult] = None
        for url in self._homepage_variants(initial_url):
            res = self._safe_get(url, max_bytes=MAX_HTML_BYTES)
            if res is None:
                continue
            if res.status >= 400:
                # Host is alive (WAF / error page). Remember it, but keep looking for a 2xx.
                if error_page is None:
                    error_page = res
                continue
            if not res.looks_like_html():
                return None, res.url
            soup = self._parse_html(res)
            final_url = res.url
            refresh = self._meta_refresh_target(soup, final_url)
            if refresh and refresh != final_url and not soup.find("link", rel=True):
                hop = self._safe_get(refresh, max_bytes=MAX_HTML_BYTES)
                if hop is not None and hop.status < 400 and hop.looks_like_html():
                    return self._parse_html(hop), hop.url
            return soup, final_url

        if error_page is not None:
            soup = self._parse_html(error_page) if error_page.looks_like_html() else None
            return soup, error_page.url
        return None, initial_url

    # -------------------------------------------------------- Discovery
    @staticmethod
    def _effective_base(soup: BeautifulSoup, page_url: str) -> str:
        base = soup.find("base", href=True)
        return urljoin(page_url, base["href"].strip()) if base else page_url

    def extract_html_icon_candidates(
        self, html, base_url: str
    ) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        Parses HTML to find favicon <link> tags, meta images, and webmanifest links.
        Accepts raw HTML (str/bytes) or a BeautifulSoup object.
        Returns (icon_candidates, manifest_urls).
        """
        soup = html if isinstance(html, BeautifulSoup) else BeautifulSoup(html, "html.parser")
        base_url = self._effective_base(soup, base_url)

        candidates: List[Dict[str, Any]] = []
        manifest_urls: List[str] = []
        seen: Set[str] = set()

        def add(url: str, **info):
            if url and url not in seen:
                seen.add(url)
                candidates.append({"url": url, **info})

        # 1. <link> tags
        for link in soup.find_all("link"):
            href = (link.get("href") or "").strip()
            if not href:
                continue
            rels = _rel_tokens(link)
            resolved = href if href.lower().startswith("data:") else urljoin(base_url, href)

            if "manifest" in rels:
                if resolved not in manifest_urls and not resolved.startswith("data:"):
                    manifest_urls.append(resolved)
                continue

            if not rels & ICON_REL_TOKENS:
                continue
            sizes = str(link.get("sizes") or "").lower()
            if rels & {"apple-touch-icon", "apple-touch-icon-precomposed"}:
                priority = 50
            elif "icon" in rels:
                is_small = any(s in sizes for s in SMALL_ICON_SIZES)
                priority = 95 if is_small or urlparse(resolved).path.lower().endswith(".ico") else 85
            else:
                priority = 40
            add(
                resolved,
                source=f"html:<link rel='{' '.join(sorted(rels))}'>",
                declared_sizes=link.get("sizes"),
                declared_type=link.get("type"),
                priority=priority,
                kind="favicon",
            )

        # 2. Windows tile image
        ms_tile = soup.find("meta", attrs={"name": re.compile(r"^msapplication-tileimage$", re.I)})
        if ms_tile and ms_tile.get("content"):
            add(urljoin(base_url, ms_tile["content"].strip()), source="html:<meta msapplication-TileImage>", priority=35, kind="favicon")

        # 3. Optional: logo and brand images (hashed for pHash / URLScan, not favicon engines)
        if self.include_logos:
            for logo_url, src in self._logo_candidates(soup, base_url):
                if sum(1 for c in candidates if c.get("kind") == "logo") >= MAX_LOGO_CANDIDATES:
                    break
                add(logo_url, source=src, priority=10, kind="logo")

        return candidates, manifest_urls

    @staticmethod
    def _logo_candidates(soup: BeautifulSoup, base_url: str) -> List[Tuple[str, str]]:
        found: List[Tuple[str, str]] = []

        # JSON-LD Organization logo
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
                    logo = node.get("logo")
                    if isinstance(logo, dict):
                        logo = logo.get("url") or logo.get("contentUrl")
                    if isinstance(logo, str) and logo.strip():
                        found.append((urljoin(base_url, logo.strip()), "html:<json-ld logo>"))
                    stack.extend(v for v in node.values() if isinstance(v, (dict, list)))

        for prop in ("og:image", "og:image:url", "og:image:secure_url", "twitter:image", "twitter:image:src"):
            for meta in soup.find_all("meta", attrs={"property": prop}) + soup.find_all("meta", attrs={"name": prop}):
                if meta.get("content"):
                    found.append((urljoin(base_url, meta["content"].strip()), f"html:<meta {prop}>"))

        img_logos = 0
        for img in soup.find_all("img"):
            if img_logos >= MAX_IMG_LOGOS:
                break
            src = img.get("src") or img.get("data-src") or ""
            if not src and img.get("srcset"):
                src = img["srcset"].split(",")[0].strip().split(" ")[0]
            src = src.strip()
            if not src or src.lower().startswith("data:"):
                continue
            attrs_str = " ".join(
                str(img.get(a, "")) for a in ("class", "id", "alt", "title")
            ).lower() + " " + src.lower()
            if "logo" in attrs_str:
                found.append((urljoin(base_url, src), "html:<img logo>"))
                img_logos += 1
        return found

    def parse_manifest_candidates(self, manifest_url: str) -> List[Dict[str, Any]]:
        """
        Fetches and parses a webmanifest file to extract icons.
        """
        candidates: List[Dict[str, Any]] = []
        res = self._safe_get(manifest_url, max_bytes=512 * 1024)
        if res is None or res.status != 200 or not res.content:
            return candidates

        try:
            data = json.loads(res.content.decode("utf-8-sig", errors="replace"))
        except Exception:
            return candidates
        if not isinstance(data, dict) or not isinstance(data.get("icons"), list):
            return candidates

        for icon in data["icons"]:
            if not isinstance(icon, dict) or not isinstance(icon.get("src"), str) or not icon["src"].strip():
                continue
            src = icon["src"].strip()
            icon_url = src if src.lower().startswith("data:") else urljoin(res.url, src)
            sizes_val = str(icon.get("sizes") or "")
            candidates.append({
                "url": icon_url,
                "source": f"manifest:{manifest_url}",
                "declared_sizes": icon.get("sizes"),
                "declared_type": icon.get("type"),
                "purpose": icon.get("purpose"),
                "priority": 60 if any(s in sizes_val for s in SMALL_ICON_SIZES) else 30,
                "kind": "favicon",
            })
        return candidates

    @staticmethod
    def _root(url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def get_fallback_candidates(self, *page_urls: str) -> List[Dict[str, Any]]:
        """
        Root-level fallback icon paths. Probed on the final (post-redirect) host and on the
        originally requested host, since search engines index both hosts separately.
        """
        out: List[Dict[str, Any]] = []
        roots = list(dict.fromkeys(self._root(u) for u in page_urls if u))
        for idx, root in enumerate(roots):
            out.extend([
                {"url": root + "/favicon.ico", "source": "fallback:/favicon.ico", "priority": 100 - idx, "kind": "favicon"},
                {"url": root + "/apple-touch-icon.png", "source": "fallback:/apple-touch-icon.png", "priority": 45, "kind": "favicon"},
                {"url": root + "/apple-touch-icon-precomposed.png", "source": "fallback:/apple-touch-icon-precomposed.png", "priority": 44, "kind": "favicon"},
            ])
        return out

    def get_manifest_fallback_urls(self, base_url: str) -> List[str]:
        """
        Common root-level fallback manifest paths.
        """
        root = self._root(base_url)
        return [root + "/manifest.json", root + "/site.webmanifest", root + "/manifest.webmanifest"]

    def probe_common_subdomains(self, domain: str) -> List[Dict[str, Any]]:
        """
        Probes common enterprise subdomains for additional favicon files
        (careers, portal, vpn, extranet, ...). Uses the registrable domain from the
        Public Suffix List, so bbc.co.uk probes careers.bbc.co.uk, never careers.co.uk.
        Icons whose final URL lands on a different organization (e.g. mail -> Outlook,
        login -> Okta) are discarded during download.
        """
        root_domain = registrable_domain(domain)
        if not root_domain:
            return []

        common_prefixes = ["careers", "portal", "vpn", "extranet", "mail", "sts", "login", "secure", "auth", "app"]
        return [
            {
                "url": f"https://{prefix}.{root_domain}/favicon.ico",
                "source": f"subdomain:{prefix}.{root_domain}",
                "priority": 75,
                "kind": "subdomain",
                "require_same_org": root_domain,
            }
            for prefix in common_prefixes
        ]

    # ----------------------------------------------------- Download & hash
    def _load_candidate(self, cand: Dict[str, Any]) -> Optional[Tuple[bytes, str]]:
        url = cand["url"]
        if url.lower().startswith("data:"):
            content = decode_data_uri(url)
            return (content, url) if content else None

        res = self._safe_get(url)
        if res is None or res.status != 200 or not res.content:
            return None
        org = cand.get("require_same_org")
        if org and not same_organization(urlparse(res.url).hostname or "", org):
            logger.debug(f"Skipping {url}: redirected off-organization to {res.url}")
            return None
        return res.content, res.url

    def download_and_analyze_icons(
        self, candidates: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Downloads icon candidates concurrently, rejects non-image responses (soft-404 HTML,
        XML/JSON error bodies), deduplicates by content hash and computes all hashes.
        Results are ordered by candidate priority (primary /favicon.ico first).
        """
        sorted_candidates: List[Dict[str, Any]] = []
        seen_urls: Set[str] = set()
        for cand in sorted(candidates, key=lambda c: c.get("priority", 0), reverse=True):
            if cand["url"] not in seen_urls:
                seen_urls.add(cand["url"])
                sorted_candidates.append(cand)

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            loaded = list(pool.map(self._load_candidate, sorted_candidates))

        results: List[Dict[str, Any]] = []
        by_sha: Dict[str, Dict[str, Any]] = {}
        primary_assigned = False

        for cand, item in zip(sorted_candidates, loaded):
            if not item:
                continue
            content, final_url = item
            if not is_image_bytes(content):
                continue

            analysis = analyze_icon_bytes(content)
            sha256 = analysis["sha256"]
            if sha256 in by_sha:
                # Same bytes already recorded from another URL / tag
                aliases = by_sha[sha256].setdefault("also_found_at", [])
                if cand["url"] not in aliases:
                    aliases.append(cand["url"])
                continue

            kind = cand.get("kind", "favicon")
            is_primary = kind == "favicon" and not primary_assigned
            primary_assigned = primary_assigned or is_primary

            icon_entry = {
                "url": cand["url"],
                "final_url": final_url if final_url != cand["url"] else None,
                "kind": kind,
                "is_primary": is_primary,
                "source": cand.get("source", "unknown"),
                "declared_sizes": cand.get("declared_sizes"),
                "declared_type": cand.get("declared_type"),
                "mmh3": analysis["mmh3"],
                "md5": analysis["md5"],
                "sha256": sha256,
                "phash": analysis["phash"],
                "format": analysis["format"],
                "dimensions": analysis["dimensions"],
                "size_bytes": analysis["size_bytes"],
                "_raw_bytes": content,  # Used if saving icons to disk / previews
            }
            by_sha[sha256] = icon_entry
            results.append(icon_entry)

        return results

    # ---------------------------------------------------------------- Scan
    def scan(self, target: str) -> Dict[str, Any]:
        """
        High-level scan workflow for a given domain/URL.
        """
        domain, initial_url = self.normalize_target(target)
        soup, final_url = self.fetch_homepage(initial_url)
        self.last_soup = soup  # kept for callers that need the homepage HTML (brand profiling)

        all_candidates: List[Dict[str, Any]] = []
        manifest_urls: List[str] = []

        if soup is not None:
            html_candidates, manifests_from_html = self.extract_html_icon_candidates(soup, final_url)
            all_candidates.extend(html_candidates)
            manifest_urls.extend(manifests_from_html)

        if not manifest_urls:
            manifest_urls.extend(self.get_manifest_fallback_urls(final_url))

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            for m_candidates in pool.map(self.parse_manifest_candidates, manifest_urls):
                all_candidates.extend(m_candidates)

        all_candidates.extend(self.get_fallback_candidates(final_url, initial_url))

        if self.probe_subdomains:
            all_candidates.extend(self.probe_common_subdomains(domain))

        icons_analyzed = self.download_and_analyze_icons(all_candidates)

        return {
            "domain": domain,
            "resolved_url": final_url,
            "reachable": soup is not None or bool(icons_analyzed),
            "icons": icons_analyzed,
        }
