"""Immutable component metadata embedded in packaged Workers."""

from __future__ import annotations

import json
from pathlib import Path
import sys

from .version import COMPLETE_VERSION, WORKER_API_VERSION


def _load() -> dict:
    roots = []
    bundle_root = getattr(sys, "_MEIPASS", None)
    if bundle_root:
        roots.append(Path(bundle_root))
    roots.append(Path(__file__).resolve().parents[1])
    for root in roots:
        path = root / "complete" / "build-info.json"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict):
            return payload
    return {
        "traffictracer": {"version": COMPLETE_VERSION, "commit": "unknown"},
        "mihomo": {"version": "unknown", "commit": "unknown"},
        "clash_verge_rev": {"version": "unknown", "commit": "unknown"},
        "worker_api": WORKER_API_VERSION,
    }


BUILD_INFO = _load()


def component_versions_dict() -> dict:
    """Return a defensive copy suitable for Worker and Session contracts."""
    return json.loads(json.dumps(BUILD_INFO))
