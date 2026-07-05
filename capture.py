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


def main():
    parser = argparse.ArgumentParser(
        description="TrafficTracer Capture Pipeline",
    )
    parser.add_argument("--config", "-c", required=True,
                        help="Path to YAML config file")
    parser.add_argument("--only", "-o",
                        help="Only capture this domain")
    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"Error loading config: {e}", file=sys.stderr)
        sys.exit(1)

    session_dir = run_capture(config, only_domain=args.only)
    print(f"Capture session saved to: {session_dir}")


if __name__ == "__main__":
    main()
