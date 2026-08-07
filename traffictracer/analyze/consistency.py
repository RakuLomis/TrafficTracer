"""Cross-index invariants for one analysis generation."""

from __future__ import annotations

from collections import defaultdict

from .request_observation import NON_NETWORK_OBSERVATIONS


class AnalysisConsistencyError(ValueError):
    """Raised when persisted analysis indexes contradict each other."""


def validate_analysis_consistency(
    request_records: list[dict],
    connection_records: list[dict],
    flow_records: list[dict],
    *,
    pcap_payload: dict | None = None,
    legacy_payload: dict | None = None,
    generation_id: str = "",
) -> dict:
    errors: list[str] = []
    request_keys: set[tuple[str, str]] = set()
    request_ids_by_connection: dict[str, set[str]] = defaultdict(set)
    urls_by_connection: dict[str, set[str]] = defaultdict(set)
    connections = {
        item.get("connection_id"): item
        for item in connection_records
        if item.get("connection_id")
    }

    for request in request_records:
        request_id = request.get("request_id")
        if not request_id:
            continue
        request_key = (request_id, request.get("url", ""))
        if request_key in request_keys:
            errors.append(f"duplicate request record: {request_id}")
        request_keys.add(request_key)
        connection_id = request.get("connection_id")
        observation = request.get("network_observation")
        status = request.get("attribution", {}).get("status")
        if observation in NON_NETWORK_OBSERVATIONS and connection_id is not None:
            errors.append(
                f"non-network request has connection_id: {request_id}"
            )
        if status == "matched":
            if not connection_id or connection_id not in connections:
                errors.append(
                    f"matched request references missing connection: {request_id}"
                )
                continue
            request_ids_by_connection[connection_id].add(request_id)
            if request.get("url"):
                urls_by_connection[connection_id].add(request["url"])

    for connection_id, connection in connections.items():
        expected_requests = request_ids_by_connection.get(connection_id, set())
        actual_requests = set(connection.get("request_ids", []))
        if actual_requests != expected_requests:
            errors.append(
                f"connection request_ids mismatch: {connection_id}"
            )
        expected_urls = urls_by_connection.get(connection_id, set())
        actual_urls = set(connection.get("urls", []))
        if actual_urls != expected_urls:
            errors.append(f"connection urls mismatch: {connection_id}")
        primary_url = connection.get("primary_url")
        if primary_url is not None and primary_url not in actual_urls:
            errors.append(f"connection primary_url mismatch: {connection_id}")

    flows_by_mihomo = {
        item.get("conn_id"): item
        for item in flow_records
        if item.get("conn_id")
    }
    connection_flow_orphans = 0
    if flow_records:
        expected_by_mihomo: dict[str, dict[str, set[str]]] = defaultdict(
            lambda: {
                "request_ids": set(),
                "connection_ids": set(),
                "urls": set(),
            }
        )
        for connection_id, connection in connections.items():
            if connection.get("match", {}).get("status") != "matched":
                continue
            mihomo_id = connection.get("mihomo_connection_id")
            if not mihomo_id:
                continue
            if mihomo_id not in flows_by_mihomo:
                connection_flow_orphans += 1
                errors.append(
                    f"connection references missing core flow: {connection_id}"
                )
                continue
            expected = expected_by_mihomo[mihomo_id]
            expected["request_ids"].update(connection.get("request_ids", []))
            expected["connection_ids"].add(connection_id)
            expected["urls"].update(connection.get("urls", []))
        for mihomo_id, expected in expected_by_mihomo.items():
            flow = flows_by_mihomo[mihomo_id]
            for field in ("request_ids", "connection_ids", "urls"):
                if set(flow.get(field, [])) != expected[field]:
                    errors.append(
                        f"core flow {field} mismatch: {mihomo_id}"
                    )

    pcap_connection_orphans = 0
    if pcap_payload:
        if generation_id and pcap_payload.get("analysis_generation_id") != generation_id:
            errors.append("pcap index uses a different analysis generation")
        for pcap in pcap_payload.get("connections", []):
            connection_id = pcap.get("connection_id")
            connection = connections.get(connection_id)
            if connection is None:
                pcap_connection_orphans += 1
                errors.append(
                    f"pcap references missing connection: {connection_id}"
                )
                continue
            if not set(pcap.get("request_ids", [])).issubset(
                set(connection.get("request_ids", []))
            ):
                errors.append(
                    f"pcap request_ids exceed connection attribution: {connection_id}"
                )

    legacy_projection_mismatches = 0
    if legacy_payload:
        legacy_ids = {
            flow.get("stable_connection_id")
            for value in legacy_payload.values()
            if isinstance(value, dict)
            for flow in value.get("flows", [])
            if flow.get("stable_connection_id")
        }
        expected_legacy_ids = {
            connection_id
            for connection_id, connection in connections.items()
            if connection.get("match", {}).get("status") == "matched"
            and request_ids_by_connection.get(connection_id)
        }
        legacy_projection_mismatches = len(
            legacy_ids.symmetric_difference(expected_legacy_ids)
        )
        if legacy_projection_mismatches:
            errors.append("legacy correlation differs from canonical v2 projection")

    if errors:
        raise AnalysisConsistencyError(
            "ANALYSIS_CONSISTENCY_FAILED: " + "; ".join(sorted(set(errors)))
        )

    return {
        "status": "passed",
        "request_connection_orphans": 0,
        "connection_flow_orphans": connection_flow_orphans,
        "pcap_connection_orphans": pcap_connection_orphans,
        "non_network_with_connection": 0,
        "legacy_projection_mismatches": legacy_projection_mismatches,
    }
