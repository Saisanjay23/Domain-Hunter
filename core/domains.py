"""
Public-suffix aware domain helpers.

Uses tldextract's bundled Public Suffix List snapshot (no network fetch), so that
multi-part TLDs such as .co.uk, .com.au or .co.in are handled correctly:
  bbc.co.uk        -> registrable "bbc.co.uk", brand label "bbc"
  shop.gi-de.com   -> registrable "gi-de.com", brand label "gi-de"
"""

from typing import Optional, Tuple
from urllib.parse import urlparse

import tldextract

# suffix_list_urls=() forces the bundled PSL snapshot: deterministic and offline.
# Private suffixes (github.io, azurewebsites.net, ...) are included so that
# tenant1.github.io and tenant2.github.io are NOT treated as the same organization.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)


def normalize_host(host: str) -> str:
    """Lowercases a hostname, strips port, userinfo, trailing dot and IDN-encodes it."""
    host = (host or "").strip().lower()
    if "://" in host:
        host = urlparse(host).netloc
    host = host.rsplit("@", 1)[-1]
    if host.startswith("["):  # IPv6 literal
        return host.split("]")[0] + "]"
    host = host.split(":")[0].strip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    return host


def split_host(host: str) -> Tuple[str, str, str]:
    """Returns (subdomain, domain_label, suffix) for a hostname."""
    ext = _EXTRACT(normalize_host(host))
    return ext.subdomain, ext.domain, ext.suffix


def registrable_domain(host: str) -> Optional[str]:
    """Returns the registrable domain (eTLD+1), or None for IPs / bare suffixes."""
    _, label, suffix = split_host(host)
    if label and suffix:
        return f"{label}.{suffix}"
    return None


def looks_like_domain(text: str) -> bool:
    """True if text is a hostname whose suffix is a known public suffix (e.g. paypal.com, bbc.co.uk)."""
    text = (text or "").strip()
    if not text or " " in text or "&" in text:
        return False
    _, label, suffix = split_host(text)
    return bool(label and suffix)


def same_organization(host_a: str, host_b: str) -> bool:
    """True if both hosts share the same registrable domain."""
    ra, rb = registrable_domain(host_a), registrable_domain(host_b)
    return bool(ra and rb and ra == rb)


def defang(value: str) -> str:
    """Defangs a domain or URL (http -> hxxp, . -> [.]) for safe indicator sharing."""
    return (value or "").replace("http", "hxxp").replace(".", "[.]")
