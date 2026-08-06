"""Reconcile derived PCAP metadata with finalized request attribution."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

from traffictracer.session.atomic import write_json_atomic

from .pcap_splitter import ConnectionPcapResult


def reconcile_pcap_attribution(
    output_dir: str | Path,
    requests: list[dict],
    pcap_results: list[ConnectionPcapResult],
) -> None:
    """Update indexes and resource mappings after final request resolution."""
    request_ids_by_connection: dict[str, set[str]] = {}
    urls_by_connection: dict[str, set[str]] = {}
    for request in requests:
        connection_id = request.get("connection_id")
        if not connection_id:
            continue
        request_ids_by_connection.setdefault(connection_id, set()).add(
            request["request_id"]
        )
        urls_by_connection.setdefault(connection_id, set()).add(request["url"])

    for index, result in enumerate(pcap_results):
        request_ids = request_ids_by_connection.get(result.connection_id, set())
        if request_ids:
            pcap_results[index] = replace(
                result,
                request_ids=tuple(sorted(set(result.request_ids) | request_ids)),
            )

    pcap_root = Path(output_dir) / "pcap"
    if not pcap_root.is_dir():
        return
    for mapping_path in sorted(pcap_root.glob("*/mapping.json")):
        try:
            mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        connection_ids = {
            item.get("connection_id")
            for item in mapping.get("connections", [])
            if isinstance(item, dict) and item.get("connection_id")
        }
        canonical_id = mapping.get("canonical_connection_id")
        if canonical_id:
            connection_ids.add(canonical_id)
        final_request_ids = set(mapping.get("request_ids", []))
        final_urls = set(mapping.get("urls", []))
        for connection_id in connection_ids:
            final_request_ids.update(
                request_ids_by_connection.get(connection_id, set())
            )
            final_urls.update(urls_by_connection.get(connection_id, set()))
        mapping["request_ids"] = sorted(final_request_ids)
        mapping["urls"] = sorted(final_urls)
        write_json_atomic(mapping_path, mapping)
