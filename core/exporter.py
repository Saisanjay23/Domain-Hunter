import csv
import json
import os
import re
from typing import Dict, Any, List

from .query_gen import fofa_icon_query, shodan_icon_query, censys_md5_query, censys_sha256_query, urlscan_hash_query

def _rich():
    """rich costs ~250 ms to import and only the terminal reports use it: load it on demand."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    return Console(), Panel, Table, Text


def clean_icon_dict_for_export(icon: Dict[str, Any]) -> Dict[str, Any]:
    """
    Removes temporary or private keys like _raw_bytes.
    """
    export_dict = {}
    keys = [
        "url", "final_url", "kind", "is_primary", "source", "declared_sizes", "declared_type", "format",
        "dimensions", "size_bytes", "mmh3", "md5", "sha256", "phash", "also_found_at",
    ]
    for k in keys:
        if k in icon:
            export_dict[k] = icon[k]
    return export_dict


def export_to_json(data: Dict[str, Any], file_path: str, indent: int = 2) -> None:
    """
    Exports scan results to a formatted JSON file.
    """
    # Clean data copy
    cleaned = {
        "domain": data.get("domain"),
        "resolved_url": data.get("resolved_url"),
        "reachable": data.get("reachable"),
        "icons": [clean_icon_dict_for_export(icon) for icon in data.get("icons", [])],
        "queries": data.get("queries", {}),
    }

    os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(cleaned, f, indent=indent)


def export_to_csv(data_list: List[Dict[str, Any]], file_path: str) -> None:
    """
    Exports list of scan results or single domain result to a flattened CSV.
    """
    os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
    fieldnames = [
        "domain",
        "resolved_url",
        "icon_url",
        "kind",
        "is_primary",
        "format",
        "dimensions",
        "size_bytes",
        "mmh3",
        "md5",
        "sha256",
        "phash",
        "fofa_query",
        "shodan_query",
        "censys_md5_query",
        "censys_sha256_query",
        "urlscan_query",
    ]

    with open(file_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for scan_data in data_list:
            domain = scan_data.get("domain", "")
            resolved_url = scan_data.get("resolved_url", "")
            icons = scan_data.get("icons", [])

            if not icons:
                writer.writerow({
                    "domain": domain,
                    "resolved_url": resolved_url,
                    "icon_url": "No icons found",
                })
                continue

            for icon in icons:
                mmh3_val = icon.get("mmh3")
                md5_val = icon.get("md5")
                sha256_val = icon.get("sha256")
                favicon_like = icon.get("kind", "favicon") != "logo"

                writer.writerow({
                    "domain": domain,
                    "resolved_url": resolved_url,
                    "icon_url": icon.get("url", ""),
                    "kind": icon.get("kind", ""),
                    "is_primary": icon.get("is_primary", ""),
                    "format": icon.get("format", ""),
                    "dimensions": icon.get("dimensions", ""),
                    "size_bytes": icon.get("size_bytes", ""),
                    "mmh3": mmh3_val,
                    "md5": md5_val,
                    "sha256": sha256_val,
                    "phash": icon.get("phash", ""),
                    "fofa_query": fofa_icon_query([mmh3_val]) if favicon_like and mmh3_val is not None else "",
                    "shodan_query": shodan_icon_query([mmh3_val]) if favicon_like and mmh3_val is not None else "",
                    "censys_md5_query": censys_md5_query([md5_val]) if favicon_like and md5_val else "",
                    "censys_sha256_query": censys_sha256_query([sha256_val]) if favicon_like and sha256_val else "",
                    "urlscan_query": urlscan_hash_query([sha256_val]) if sha256_val else "",
                })


def save_icon_files(icons: List[Dict[str, Any]], output_dir: str, domain_prefix: str = "") -> List[str]:
    """
    Saves raw icon bytes to local disk for manual inspection.
    """
    saved_paths = []
    os.makedirs(output_dir, exist_ok=True)

    safe_domain = re.sub(r"[^\w\-_\.]", "_", domain_prefix) if domain_prefix else "icon"

    for idx, icon in enumerate(icons):
        raw_bytes = icon.get("_raw_bytes")
        if not raw_bytes:
            continue

        ext = "ico"
        fmt = (icon.get("format") or "").lower()
        fmt_ext = {"jpeg": "jpg", "mpo": "jpg", "cur": "cur", "bmp": "bmp", "avif": "avif"}
        if fmt in ["png", "ico", "jpeg", "jpg", "gif", "webp", "svg", "mpo", "cur", "bmp", "avif"]:
            ext = fmt_ext.get(fmt, fmt)
        else:
            # Check url extension
            url_part = icon.get("url", "").split("?")[0]
            if "." in url_part:
                maybe_ext = url_part.split(".")[-1].lower()
                if len(maybe_ext) <= 4 and maybe_ext in ["ico", "png", "svg", "jpg", "jpeg", "gif", "webp"]:
                    ext = maybe_ext

        md5_short = (icon.get("md5") or "")[:8]
        filename = f"{safe_domain}_{idx}_{md5_short}.{ext}"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "wb") as f:
            f.write(raw_bytes)
        saved_paths.append(filepath)

    return saved_paths


def print_rich_report(scan_result: Dict[str, Any]) -> None:
    """
    Prints a rich interactive CLI dashboard for a domain scan.
    """
    console, Panel, Table, Text = _rich()
    domain = scan_result.get("domain", "Unknown")
    resolved = scan_result.get("resolved_url", "")
    icons = scan_result.get("icons", [])
    queries = scan_result.get("queries", {})

    # Title panel
    console.print()
    banner_text = Text()
    banner_text.append("Domain Favicon & Threat Intel Hash Scanner\n", style="bold cyan")
    banner_text.append(f"Target: {domain}  |  Resolved: {resolved}  |  Discovered Icons: {len(icons)}", style="white")
    console.print(Panel(banner_text, border_style="cyan"))

    # Icons Table
    if not icons:
        console.print("[yellow]No favicons or icons could be retrieved for this domain.[/yellow]")
        return

    table = Table(title=f"Discovered Icons & Hashes for {domain}", show_lines=True)
    table.add_column("Icon URL", style="blue", overflow="fold", max_width=45)
    table.add_column("Kind", style="white", justify="center")
    table.add_column("Type/Dim", style="magenta", justify="center")
    table.add_column("MMH3 (Shodan/FOFA)", style="bold green", justify="center")
    table.add_column("MD5 (Censys)", style="yellow", overflow="fold")
    table.add_column("pHash (Visual)", style="cyan", justify="center")

    for icon in icons:
        dim_str = f"{icon.get('format') or '?'}\n{icon.get('dimensions') or 'N/A'}"
        mmh3_str = str(icon.get("mmh3", "N/A"))
        md5_str = str(icon.get("md5", "N/A"))
        phash_str = str(icon.get("phash", "N/A"))
        url_str = icon.get("url", "")
        if url_str.startswith("data:"):
            url_str = url_str[:40] + "..."
        kind_str = (icon.get("kind") or "favicon") + (" [primary]" if icon.get("is_primary") else "")
        table.add_row(
            url_str,
            kind_str,
            dim_str,
            mmh3_str,
            md5_str,
            phash_str,
        )

    console.print(table)

    # Threat Intelligence Queries Panels
    query_text = Text()
    sections = [
        ("fofa", "FOFA Queries", "bold yellow"),
        ("shodan", "Shodan Queries", "bold green"),
        ("censys", "Censys Platform Queries", "bold cyan"),
        ("urlscan", "URLScan Queries (any resource hash)", "bold magenta"),
    ]
    for key, title, style in sections:
        query_text.append(f"\n[{title}]\n", style=style)
        for q in queries.get(key, []):
            query_text.append(f"  • {q}\n", style="white")

    combined = queries.get("combined", {})
    if combined:
        query_text.append("\n[Master Combined Queries]\n", style="bold red")
        for key in ("fofa", "shodan", "censys", "urlscan"):
            if combined.get(key):
                query_text.append(f"  {key.upper():8} {combined[key]}\n", style="white")
    excluded = (queries.get("hash_counts") or {}).get("excluded_subdomain_icons")
    if excluded:
        query_text.append(
            f"\n  Note: {excluded} subdomain-portal icon(s) kept out of master queries "
            "(often shared SaaS vendor favicons).\n",
            style="dim",
        )

    console.print(Panel(query_text, title="Threat Intelligence & Search Engine Queries", border_style="green"))


# --------------------------------------------------------------------------- impersonation hunt
VERDICT_STYLES = {
    "phishing": "bold red", "suspicious": "bold yellow", "parked": "magenta", "redirect_brand": "green",
    "brand_owned": "green", "no_website": "white", "unreachable": "dim", "live_unrelated": "dim",
}


def print_hunt_report(result: Dict[str, Any], limit: int = 40) -> None:
    """Rich terminal summary of an impersonation hunt."""
    console, Panel, Table, Text = _rich()
    stats = result.get("stats", {})
    brand = result.get("brand", {})
    console.print()
    t = Text()
    t.append("Brand Impersonation Hunt\n", style="bold cyan")
    t.append(f"Brand: {result.get('target')}  |  Own domains: {', '.join(brand.get('allowlist', []))}\n", style="white")
    t.append(
        f"Generated {stats.get('generated', 0)}  |  CT hosts {stats.get('ct_hosts', 0)}  |  Registered {stats.get('registered', 0)}  |  "
        f"Live {stats.get('live', 0)}  |  High-risk {stats.get('high_risk', 0)}  |  Suspicious {stats.get('suspicious', 0)}  |  "
        f"{stats.get('elapsed_sec', 0)}s",
        style="white",
    )
    console.print(Panel(t, border_style="cyan"))
    for err in result.get("errors", [])[:5]:
        console.print(f"[yellow]! {err}[/yellow]")

    table = Table(title=f"Top {min(limit, len(result.get('candidates', [])))} lookalike domains", show_lines=False)
    table.add_column("Score", justify="right")
    table.add_column("Verdict")
    table.add_column("Domain", style="bold", overflow="fold", max_width=34)
    table.add_column("Type", style="cyan")
    table.add_column("Age", justify="right")
    table.add_column("Why", overflow="fold", max_width=70)
    for c in result.get("candidates", [])[:limit]:
        style = VERDICT_STYLES.get(c["verdict"], "white")
        age = (c.get("rdap") or {}).get("age_days")
        name = c["domain"] + (f"\n({c['unicode']})" if c.get("unicode") else "")
        table.add_row(str(c["score"]), Text(c.get("verdict_label", c["verdict"]), style=style), name, c["fuzzer"],
                      f"{age}d" if age is not None else "", "; ".join((c.get("reasons") or [])[:3]))
    console.print(table)


def export_hunt_csv(result: Dict[str, Any], file_path: str) -> None:
    from .hunter import HUNT_CSV_FIELDS, hunt_csv_rows

    os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
    with open(file_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=HUNT_CSV_FIELDS)
        writer.writeheader()
        writer.writerows(hunt_csv_rows(result))
