#!/usr/bin/env python3
"""Generate immutable Worker component metadata from the verified lock."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--traffictracer-commit", required=True)
    args = parser.parse_args()
    lock = yaml.safe_load(args.lock.read_text(encoding="utf-8"))
    commit = args.traffictracer_commit.strip()
    if len(commit) != 40 or any(char not in "0123456789abcdef" for char in commit):
        raise SystemExit("traffictracer commit must be a full lowercase Git SHA")
    components = lock["components"]
    payload = {
        "traffictracer": {
            "version": lock["product"]["version"],
            "commit": commit,
        },
        "mihomo": {
            "version": components["mihomo"]["branch"],
            "commit": components["mihomo"]["commit"],
        },
        "clash_verge_rev": {
            "version": components["clash_verge_rev"]["branch"],
            "commit": components["clash_verge_rev"]["commit"],
        },
        "worker_api": lock["protocols"]["worker_api"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
