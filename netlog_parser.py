#!/usr/bin/env python3
"""NetLog Parser — extract connection info from Chromium NetLog JSON dumps.

Usage:
  python netlog_parser.py <log.json>                  # Full analysis
  python netlog_parser.py <log.json> --summary        # Summary only
  python netlog_parser.py <log.json> --chains         # Connection chains
  python netlog_parser.py <log.json> --dns            # DNS records only
  python netlog_parser.py <log.json> --json           # JSON export
  python netlog_parser.py <log.zip>                   # ZIP from chrome://net-export
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
import zipfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Parse Chromium NetLog JSON dumps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s chrome-net-export-log.json
  %(prog)s --summary log.json
  %(prog)s --chains --url "*.example.com" log.json
  %(prog)s --json --output parsed.json log.json
  %(prog)s log.zip
        """.strip(),
    )
    parser.add_argument("file", help="NetLog JSON file or ZIP archive")
    parser.add_argument("--summary", action="store_true",
                        help="Print summary only")
    parser.add_argument("--chains", action="store_true",
                        help="Print connection chains")
    parser.add_argument("--dns", action="store_true",
                        help="Print DNS resolver cache")
    parser.add_argument("--sessions", action="store_true",
                        help="Print HTTP/2 and QUIC session reuse")
    parser.add_argument("--json", action="store_true",
                        help="Export parsed data as JSON")
    parser.add_argument("--output", "-o", type=str,
                        help="Write output to file instead of stdout")
    parser.add_argument("--start-from", type=str, choices=["url_request", "socket"],
                        default="url_request",
                        help="Trace chains starting from this source type")
    parser.add_argument("--url", type=str,
                        help="Filter chains by URL glob pattern (e.g. '*example.com*')")
    parser.add_argument("--domain", "-d", type=str,
                        help="Analyze all connections for a specific domain (e.g. 'bilibili.com'). "
                             "Groups results by name and same_site/cross_site relationship, "
                             "showing local/remote address pairs for each connection.")
    args = parser.parse_args()

    # Load the log
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    log_data = _load_log(file_path)
    if log_data is None:
        sys.exit(1)

    # Parse
    from parser.constants import NetLogConstants
    from parser.event_processor import process_events
    from parser.dns_resolver import extract_dns_info
    from parser.output import (
        print_summary, print_connection_chains, print_session_reuse,
        print_dns_info, export_json, print_domain_analysis, export_domain_json,
    )

    constants = NetLogConstants(log_data.get("constants") or {})
    events = log_data.get("events") or []
    polled_data = log_data.get("polledData") or {}

    if not isinstance(events, list):
        print("Error: 'events' field is not a list", file=sys.stderr)
        sys.exit(1)

    entries = process_events(events, constants)
    dns = extract_dns_info(polled_data, constants)

    # Determine output target
    output_file = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout

    try:
        # --domain mode: analyze connections for a specific domain
        if args.domain:
            if args.json:
                export_domain_json(entries, args.domain, file=output_file)
            else:
                print_domain_analysis(entries, args.domain, file=output_file)
        elif args.json:
            export_json(entries, constants, polled_data, dns, file=output_file)
        else:
            # Default: show everything unless specific flags are given
            show_all = not (args.summary or args.chains or args.dns or args.sessions)

            if show_all or args.summary:
                print_summary(entries, constants, file=output_file)

            if show_all or args.chains:
                print_connection_chains(entries, constants,
                                         start_from=args.start_from,
                                         url_filter=args.url,
                                         file=output_file)

            if show_all or args.sessions:
                print_session_reuse(entries, constants, polled_data,
                                     file=output_file)

            if show_all or args.dns:
                if dns:
                    print_dns_info(dns, file=output_file)
                elif not show_all and args.dns:
                    print("(No DNS resolver cache in this log)", file=output_file)
    finally:
        if args.output:
            output_file.close()


def _load_log(path: Path) -> dict | None:
    """Load NetLog JSON, transparently handling ZIP files."""
    if path.suffix.lower() == ".zip":
        return _load_from_zip(path)
    else:
        return _load_json(path)


def _load_json(path: Path) -> dict | None:
    """Load and parse a JSON file."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON: {e}", file=sys.stderr)
        return None
    except OSError as e:
        print(f"Error: cannot read file: {e}", file=sys.stderr)
        return None

    if not isinstance(data, dict):
        print("Error: root JSON element is not an object", file=sys.stderr)
        return None

    return data


def _load_from_zip(path: Path) -> dict | None:
    """Load the first .json file found inside a ZIP."""
    try:
        with zipfile.ZipFile(path, "r") as zf:
            json_files = [n for n in zf.namelist()
                          if n.lower().endswith(".json")]
            if not json_files:
                print("Error: no .json file found in ZIP", file=sys.stderr)
                return None

            if len(json_files) > 1:
                print(f"Found {len(json_files)} JSON files, using: {json_files[0]}",
                      file=sys.stderr)

            content = zf.read(json_files[0]).decode("utf-8")
            return json.loads(content)

    except zipfile.BadZipFile:
        print("Error: not a valid ZIP file", file=sys.stderr)
        return None
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON inside ZIP: {e}", file=sys.stderr)
        return None
    except OSError as e:
        print(f"Error: cannot read file: {e}", file=sys.stderr)
        return None


if __name__ == "__main__":
    main()
