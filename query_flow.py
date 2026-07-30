#!/usr/bin/env python3
"""Look up post-proxy flow(s) from one normalized pre-proxy five-tuple."""

import argparse
from dataclasses import asdict
import json

from traffictracer.analyze.flow_index import FlowIndex


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", help="Mihomo TrafficTracer JSONL path")
    parser.add_argument("network", choices=("tcp", "udp"))
    parser.add_argument("src_ip")
    parser.add_argument("src_port", type=int)
    parser.add_argument("dst_ip")
    parser.add_argument("dst_port", type=int)
    args = parser.parse_args()
    matches = FlowIndex.from_log(args.trace).lookup(
        args.network, args.src_ip, args.src_port, args.dst_ip, args.dst_port,
    )
    print(json.dumps([asdict(item) for item in matches], ensure_ascii=False, indent=2))
    return 0 if matches else 1


if __name__ == "__main__":
    raise SystemExit(main())
