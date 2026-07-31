#!/usr/bin/env python3
"""TrafficTracer Capture — collect traffic data for configured domains.

Usage:
  python capture.py --config sites.yaml
  python capture.py --config sites.yaml --only bilibili.com
"""

import argparse
import sys

from traffictracer.capture.pipeline import run_capture
from traffictracer.config import load_config


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="TrafficTracer Capture Pipeline",
    )
    parser.add_argument("--config", "-c", required=True,
                        help="Path to YAML config file")
    parser.add_argument("--only", "-o",
                        help="Only capture this domain")
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
    except Exception as exc:
        print(f"Error loading config: {exc}", file=sys.stderr)
        return 1

    try:
        session_dir = run_capture(config, only_domain=args.only)
    except KeyboardInterrupt:
        print("Capture cancelled; cleanup completed.", file=sys.stderr)
        return 130
    print(f"Capture session saved to: {session_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
