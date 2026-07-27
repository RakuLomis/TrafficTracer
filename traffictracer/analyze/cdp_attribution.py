"""CDP attribution parser — convert structured CDP JSON to AttributedRequest list."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import AttributedRequest
from ..utils import logger


def parse_cdp_attribution(path: str) -> list[AttributedRequest]:
    fp = Path(path)
    if not fp.exists():
        raise FileNotFoundError(f"CDP data file not found: {path}")

    with open(fp, "r", encoding="utf-8") as f:
        data = json.load(f)

    raw_requests = data.get("requests", [])
    result: list[AttributedRequest] = []

    for raw in raw_requests:
        url = raw.get("url", "")
        if not url:
            continue

        result.append(AttributedRequest(
            request_id=raw.get("request_id", ""),
            target_id=raw.get("target_id", ""),
            frame_id=raw.get("frame_id", ""),
            url=url,
            resource_type=raw.get("resource_type", "Other"),
            timestamp=raw.get("timestamp", 0.0),
            target_type=raw.get("target_type", "unknown"),
            loader_id=raw.get("loader_id", ""),
            initiator_type=raw.get("initiator_type", ""),
            connection_id=raw.get("connection_id"),
            remote_ip=raw.get("remote_ip", ""),
            remote_port=raw.get("remote_port", 0),
            connection_reused=raw.get("connection_reused", False),
        ))

    logger.info("Parsed %d attributed requests from CDP data", len(result))
    return result
