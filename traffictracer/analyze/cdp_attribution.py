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

    return parse_cdp_attribution_data(data)


def parse_cdp_attribution_data(data: dict) -> list[AttributedRequest]:
    """Parse an already loaded capture without retaining a second JSON tree."""

    raw_requests = data.get("requests", [])
    result: list[AttributedRequest] = []
    occurrence_counts: dict[tuple[str, str], int] = {}
    previous_by_chain: dict[tuple[str, str], dict] = {}

    for raw in raw_requests:
        url = raw.get("url", "")
        # data:, blob:, chrome-extension: and similar schemes do not create a
        # standalone HTTP transport and cannot satisfy the flow-v2 contract.
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            continue
        chain_key = (
            str(raw.get("target_id", "")),
            str(raw.get("request_id", "")),
        )
        fallback_index = occurrence_counts.get(chain_key, 0)
        redirect_index = raw.get("redirect_index", fallback_index)
        if not isinstance(redirect_index, int) or redirect_index < 0:
            redirect_index = fallback_index
        occurrence_counts[chain_key] = max(fallback_index, redirect_index) + 1
        previous = previous_by_chain.get(chain_key)
        redirect_from_url = raw.get("redirect_from_url") or ""
        redirect_status = raw.get("redirect_status") or 0
        if redirect_index > 0 and previous is not None:
            redirect_from_url = redirect_from_url or previous.get("url", "")
            previous_status = previous.get("response_status", 0)
            if not redirect_status and isinstance(previous_status, int):
                if 300 <= previous_status <= 399:
                    redirect_status = previous_status
        previous_by_chain[chain_key] = raw

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
            response_status=raw.get("response_status", 0),
            from_disk_cache=raw.get("from_disk_cache", False),
            from_service_worker=raw.get("from_service_worker", False),
            from_prefetch_cache=raw.get("from_prefetch_cache", False),
            response_timestamp=raw.get("response_timestamp", 0.0),
            completion_timestamp=raw.get("completion_timestamp", 0.0),
            failed=raw.get("failed", False),
            canceled=raw.get("canceled", False),
            failure_reason=raw.get("failure_reason", ""),
            redirect_index=redirect_index,
            redirect_from_url=redirect_from_url,
            redirect_status=redirect_status,
        ))

    logger.info("Parsed %d attributed requests from CDP data", len(result))
    return result
