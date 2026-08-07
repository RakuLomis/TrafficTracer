"""Classify whether a browser request should have packet-bearing transport."""

from __future__ import annotations


NON_NETWORK_OBSERVATIONS = frozenset({
    "disk_cache",
    "service_worker",
    "prefetch_cache",
    "browser_internal",
})


def request_network_observation(request) -> tuple[str, list[str]]:
    """Return the canonical network observation and its CDP evidence."""
    if request.from_service_worker:
        return "service_worker", ["cdp_from_service_worker"]
    if request.from_prefetch_cache:
        return "prefetch_cache", ["cdp_from_prefetch_cache"]
    if request.from_disk_cache:
        return "disk_cache", ["cdp_from_disk_cache"]
    if request.remote_ip or (
        request.connection_id is not None and request.connection_id > 0
    ):
        return "network", ["request_not_in_transport_index"]
    if request.connection_id == 0 and request.response_status > 0:
        return "browser_internal", [
            "cdp_connection_id_zero",
            "cdp_response_received",
        ]
    return "unknown", ["request_not_in_transport_index"]


def request_can_have_transport(request) -> bool:
    """Reject cache/internal responses before any endpoint or host fallback."""
    observation, _ = request_network_observation(request)
    return observation not in NON_NETWORK_OBSERVATIONS
