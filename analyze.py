#!/usr/bin/env python3
"""TrafficTracer Analysis — correlate and split captured traffic data.

Usage:
  python analyze.py --session output/2025-07-05_14-30-00/
"""

import argparse
import sys

from traffictracer.analyze.pipeline import run_analysis


def main():
    parser = argparse.ArgumentParser(
        description="TrafficTracer Analysis Pipeline",
    )
    parser.add_argument("--session", "-s", required=True,
                        help="Path to capture session directory")
    args = parser.parse_args()

    try:
        corr_path = run_analysis(args.session)
        print(f"Correlation results: {corr_path}")
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
