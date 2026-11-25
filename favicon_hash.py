#!/usr/bin/env python3
"""
Favicon & Icon Hash Threat Intelligence Scanner
Extracts favicon and webmanifest icons, computes MMH3, MD5, SHA256, pHash,
and generates search queries for FOFA, Shodan, Censys and URLScan.
"""

import argparse
import os
import sys
from typing import Dict, Any, List, Optional

from core.crawler import FaviconCrawler
from core.query_gen import generate_search_queries
from core.platforms import PLATFORMS, build_search_url
from core.exporter import (
    print_rich_report,
    export_to_json,
    export_to_csv,
    save_icon_files,
    clean_icon_dict_for_export,
)
import webbrowser


def scan_domain(
    target: str,
    timeout: int = 10,
    include_logos: bool = True,
    probe_subdomains: bool = True,
    save_icons_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Scans a single domain or URL, extracts all icons, computes hashes,
    and generates threat intel search engine queries.
    """
    crawler = FaviconCrawler(
        timeout=timeout,
        include_logos=include_logos,
        probe_subdomains=probe_subdomains,
    )
    result = crawler.scan(target)

    # Generate OSINT queries
    queries = generate_search_queries(result["icons"])
    result["queries"] = queries

    # Optionally save icon files to local disk
    if save_icons_dir:
        domain_folder = os.path.join(save_icons_dir, result["domain"])
        saved = save_icon_files(result["icons"], domain_folder, domain_prefix=result["domain"])
        result["saved_icon_files"] = saved

    return result


def launch_queries_in_browser(queries: Dict[str, Any]) -> None:
    """
    Opens all master combined threat intelligence queries (FOFA, Shodan, Censys, URLScan)
    in the default browser in one go.
    """
    combined = queries.get("combined", {})
    opened = 0
    for platform in PLATFORMS:
        q = combined.get(platform) or next(iter(queries.get(platform) or []), None)
        if q:
            webbrowser.open(build_search_url(platform, q))
            opened += 1

    print(f"\n[*] [One-Go Launch] Opened {opened} threat intelligence search tabs in default browser.")


def launch_fofa_tabs_in_browser(icons: List[Dict[str, Any]]) -> None:
    """
    Opens each unique FOFA MMH3 hash (favicon-type icons only) in its own separate browser tab.
    """
    unique_hashes = list(dict.fromkeys(
        ic["mmh3"] for ic in icons
        if ic.get("mmh3") is not None and ic.get("kind", "favicon") != "logo"
    ))
    if not unique_hashes:
        print("[-] No MMH3 hashes available to launch for FOFA.")
        return

    for val in unique_hashes:
        webbrowser.open(build_search_url("fofa", f'icon_hash="{val}"'))

    print(f"\n[*] [FOFA Multi-Tab Launch] Opened {len(unique_hashes)} individual FOFA hash tab(s) in default browser.")


def run_hunt_cli(args) -> None:
    import json
    from core.hunter import run_hunt, hunt_for_export
    from core.exporter import print_hunt_report, export_hunt_csv

    def split(v):
        return [x.strip() for x in (v or "").split(",") if x.strip()]

    last = {"stage": None}

    def progress(stage, pct, msg, _stats):
        if not args.quiet and (stage != last["stage"] or stage in ("dns", "verify")):
            print(f"\r[{pct:5.1f}%] {msg:<80}", end="" if stage in ("dns", "verify") else "\n", flush=True)
            last["stage"] = stage

    result = run_hunt(args.hunt, depth=args.depth, use_ct=not args.no_ct, verify=not args.no_verify,
                      use_rdap=not args.no_rdap, use_intel=not args.no_intel, use_feeds=not args.no_feeds, extra_allowlist=split(args.allow), extra_keywords=split(args.keywords),
                      timeout=min(args.timeout, 15), progress=progress)
    if not args.no_save:
        import uuid
        from core.store import get_store

        try:
            export = hunt_for_export(result)
            hunt_id = uuid.uuid4().hex[:12]
            store = get_store()
            store.decorate(export, exclude_id=hunt_id)  # adds new-since-last-hunt flags and case status
            export["hunt_id"] = hunt_id
            store.save_hunt(hunt_id, export)
            result["candidates"] = export["candidates"]
            result["stats"] = export["stats"]
            new = result["stats"].get("new_domains")
            if not args.quiet and result["stats"].get("has_previous"):
                print(f"[+] Saved to history ({hunt_id}). {new} new domain(s) since the previous hunt.")
            elif not args.quiet:
                print(f"[+] Saved to history ({hunt_id}). First hunt of this brand: future hunts will show what is new.")
        except Exception as e:
            print(f"[!] Could not save to history: {e}", file=sys.stderr)
    if not args.quiet:
        print()
        print_hunt_report(result)
    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(hunt_for_export(result), f, indent=2, default=list)
        print(f"[+] Exported JSON to: {args.json}")
    if args.csv:
        export_hunt_csv(result, args.csv)
        print(f"[+] Exported CSV to: {args.csv}")


def main():
    parser = argparse.ArgumentParser(
        description="Favicon & Icon Hash Threat Intelligence Scanner (MMH3, MD5, SHA256, pHash)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python favicon_hash.py --hunt adani.com -o hunt.json -c hunt.csv
  python favicon_hash.py --hunt bbc.co.uk --depth deep --allow bbci.co.uk
  python favicon_hash.py -d gi-de.com
  python favicon_hash.py -d gi-de.com --launch
  python favicon_hash.py -d gi-de.com -o results.json -c results.csv
  python favicon_hash.py -d gi-de.com --save-icons ./downloaded_icons
  python favicon_hash.py -f domains.txt -o batch_results.json -c batch_results.csv
        """,
    )

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument(
        "-d", "--domain",
        help="Target domain or full URL (e.g. gi-de.com, https://example.com)",
    )
    group.add_argument(
        "-f", "--file",
        help="Path to a text file containing domains/URLs (one per line)",
    )
    group.add_argument(
        "--hunt",
        metavar="DOMAIN",
        help="Impersonation hunt: find live lookalike / phishing domains of a brand (e.g. --hunt adani.com)",
    )
    group.add_argument(
        "--migrate-history",
        action="store_true",
        help="Copy the local SQLite history, case notes, watchlist and alerts into MongoDB (MONGODB_URI must be set)",
    )
    group.add_argument(
        "--ui",
        action="store_true",
        help="Launch interactive Web UI dashboard on http://127.0.0.1:8080",
    )

    parser.add_argument(
        "-o", "--json",
        help="Output file path for JSON export",
        default=None,
    )
    parser.add_argument(
        "-c", "--csv",
        help="Output file path for CSV export",
        default=None,
    )
    parser.add_argument(
        "--save-icons",
        help="Directory to save downloaded icon image files",
        default=None,
    )
    parser.add_argument(
        "--no-logos",
        action="store_true",
        help="Disable automatic extraction of brand/header logos (og:image, logo img tags)",
    )
    parser.add_argument(
        "--no-subdomains",
        action="store_true",
        help="Disable automatic probing of common subdomains (careers, portal, vpn, extranet, login, etc.)",
    )
    parser.add_argument(
        "-l", "--launch",
        action="store_true",
        help="Launch all generated threat intelligence queries in your default browser in one go",
    )
    parser.add_argument(
        "--launch-fofa-tabs",
        action="store_true",
        help="Launch each unique FOFA MMH3 hash in its own separate browser tab",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP request timeout in seconds (default: 10)",
    )
    parser.add_argument("--depth", choices=["quick", "standard", "deep"], default="standard",
                        help="Hunt: permutation depth (quick ~150, standard ~600-1200, deep ~2500+ candidates)")
    parser.add_argument("--no-ct", action="store_true", help="Hunt: skip Certificate Transparency (crt.sh) search")
    parser.add_argument("--no-verify", action="store_true", help="Hunt: DNS only, do not visit candidate websites")
    parser.add_argument("--no-intel", action="store_true", help="Hunt: skip threat-intel platform queries (URLScan / Shodan / FOFA / Censys / Lens)")
    parser.add_argument("--no-feeds", action="store_true", help="Hunt: skip OpenPhish / Phishing.Database matching")
    parser.add_argument("--no-save", action="store_true", help="Hunt: do not save the result to the history database")
    parser.add_argument("--no-rdap", action="store_true", help="Hunt: skip registration-date (RDAP) lookups")
    parser.add_argument("--allow", default="", help="Hunt: extra domains the brand owns (comma-separated), never reported")
    parser.add_argument("--keywords", default="", help="Hunt: extra combosquat words (comma-separated), e.g. 'power,ports,green'")
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode: suppress terminal banner and rich tables",
    )

    args = parser.parse_args()

    if args.ui:
        from app import start_server
        start_server()
        return

    if args.migrate_history:
        from core.migrate import copy_store
        from core.store import Store, StoreUnavailable, default_path, get_store

        try:
            active = get_store()
        except StoreUnavailable as e:
            print(f"[-] {e}", file=sys.stderr)
            sys.exit(1)
        if active.backend != "mongodb":
            print("[-] MongoDB is not configured. Set MONGODB_URI in .env (or Settings > Storage) first.", file=sys.stderr)
            sys.exit(1)
        if not os.path.exists(default_path()):
            print(f"[-] No local SQLite history at {default_path()}", file=sys.stderr)
            sys.exit(1)
        local = Store(default_path())
        try:
            counts = copy_store(local, active)
        finally:
            local.close()
        print(f"[+] Copied {counts['hunts']} hunt(s), {counts['triage']} case note(s), {counts['watchlist']} watched brand(s)"
              f" ({counts['watchlist_skipped']} already present), alerts: "
              f"{'skipped (destination already has alerts)' if counts['alerts_skipped'] else counts['alerts']}.")
        return

    if args.hunt:
        run_hunt_cli(args)
        return

    if not args.domain and not args.file:
        parser.print_help()
        sys.exit(1)

    targets: List[str] = []
    if args.domain:
        targets.append(args.domain)
    elif args.file:
        if not os.path.isfile(args.file):
            print(f"[-] Error: Target file '{args.file}' does not exist.", file=sys.stderr)
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8") as f:
            targets = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    all_results: List[Dict[str, Any]] = []

    for target in targets:
        if not args.quiet:
            print(f"[*] Crawling target: {target} ...")

        include_logos = not args.no_logos
        probe_subdomains = not args.no_subdomains

        result = scan_domain(
            target=target,
            timeout=args.timeout,
            include_logos=include_logos,
            probe_subdomains=probe_subdomains,
            save_icons_dir=args.save_icons,
        )
        all_results.append(result)

        if not args.quiet:
            print_rich_report(result)

        if args.launch and result.get("queries"):
            launch_queries_in_browser(result["queries"])

        if args.launch_fofa_tabs and result.get("icons"):
            launch_fofa_tabs_in_browser(result["icons"])

    # Exports
    if args.json:
        if len(all_results) == 1:
            export_to_json(all_results[0], args.json)
        else:
            # Multi-target export
            batch_data = {
                "total_targets": len(all_results),
                "results": [
                    {
                        "domain": r["domain"],
                        "resolved_url": r["resolved_url"],
                        "reachable": r.get("reachable"),
                        "icons": [clean_icon_dict_for_export(i) for i in r["icons"]],
                        "queries": r["queries"],
                    }
                    for r in all_results
                ],
            }
            import json
            os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(batch_data, f, indent=2)
        if not args.quiet:
            print(f"[+] Exported JSON to: {args.json}")

    if args.csv:
        export_to_csv(all_results, args.csv)
        if not args.quiet:
            print(f"[+] Exported CSV to: {args.csv}")


if __name__ == "__main__":
    main()
