#!/usr/bin/env python3
"""Look up post-proxy flow(s) from one normalized pre-proxy five-tuple."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

from traffictracer.analyze.flow_index import FlowIndex, flow_key


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", nargs="?", help="Mihomo TrafficTracer JSONL path")
    parser.add_argument("network", nargs="?", choices=("tcp", "udp"))
    parser.add_argument("src_ip", nargs="?")
    parser.add_argument("src_port", nargs="?", type=int)
    parser.add_argument("dst_ip", nargs="?")
    parser.add_argument("dst_port", nargs="?", type=int)
    parser.add_argument("--session", help="Query a persisted Session flow-index.json")
    parser.add_argument("--network", dest="session_network", choices=("tcp", "udp"))
    parser.add_argument("--src-ip", dest="session_src_ip")
    parser.add_argument("--src-port", dest="session_src_port", type=int)
    parser.add_argument("--dst-ip", dest="session_dst_ip")
    parser.add_argument("--dst-port", dest="session_dst_port", type=int)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--json", action="store_true",
                        help="Print machine-readable JSON (the compatibility default)")
    args = parser.parse_args(argv)
    try:
        if args.session:
            fields = (
                args.session_network,
                args.session_src_ip,
                args.session_src_port,
                args.session_dst_ip,
                args.session_dst_port,
            )
            if any(value is None for value in fields):
                parser.error(
                    "--session requires --network, --src-ip, --src-port, "
                    "--dst-ip and --dst-port"
                )
            matches = _query_session(args.session, *fields)
        else:
            fields = (
                args.trace,
                args.network,
                args.src_ip,
                args.src_port,
                args.dst_ip,
                args.dst_port,
            )
            if any(value is None for value in fields):
                parser.error("trace and the normalized five-tuple are required")
            raw_matches = FlowIndex.from_log(args.trace).lookup(
                args.network,
                args.src_ip,
                args.src_port,
                args.dst_ip,
                args.dst_port,
            )
            matches = [asdict(item) for item in raw_matches]
        if args.offset < 0 or args.limit < 0:
            parser.error("--offset and --limit must be non-negative")
        end = args.offset + args.limit if args.limit else None
        matches = matches[args.offset:end]
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(matches, ensure_ascii=False, indent=2))
    return 0 if matches else 1


def _query_session(
    session_dir: str,
    network: str,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
) -> list[dict]:
    path = Path(session_dir).expanduser().resolve() / "results" / "flow-index.json"
    with path.open(encoding="utf-8") as stream:
        payload = json.load(stream)
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise ValueError(f"invalid persisted Flow index: {path}")
    expected = flow_key(network, src_ip, src_port, dst_ip, dst_port)
    matches = []
    for item in payload["items"]:
        if not isinstance(item, dict) or not isinstance(item.get("pre_flow"), dict):
            continue
        pre = item["pre_flow"]
        try:
            actual = flow_key(
                pre["network"],
                pre["src_ip"],
                pre["src_port"],
                pre["dst_ip"],
                pre["dst_port"],
            )
        except (KeyError, TypeError, ValueError):
            continue
        if actual == expected:
            matches.append(item)
    return matches


if __name__ == "__main__":
    raise SystemExit(main())
