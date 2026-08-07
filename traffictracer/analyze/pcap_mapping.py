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
        # The request index is authoritative after transport-race resolution.
        # Replace preliminary attribution even when the final set is empty so
        # a request moved to another connection cannot remain in PCAP metadata.
        request_ids = request_ids_by_connection.get(result.connection_id, set())
        pcap_results[index] = replace(
            result,
            request_ids=tuple(sorted(request_ids)),
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
        # Rebuild group metadata from finalized request attribution. Starting
        # with the preliminary mapping would preserve stale request IDs/URLs.
        final_request_ids: set[str] = set()
        final_urls: set[str] = set()
        for connection_id in connection_ids:
            final_request_ids.update(
                request_ids_by_connection.get(connection_id, set())
            )
            final_urls.update(urls_by_connection.get(connection_id, set()))
        mapping["request_ids"] = sorted(final_request_ids)
        mapping["urls"] = sorted(final_urls)
        current_primary = mapping.get("primary_url")
        mapping["primary_url"] = (
            current_primary
            if current_primary in final_urls
            else min(final_urls) if final_urls else None
        )
        write_json_atomic(mapping_path, mapping)
