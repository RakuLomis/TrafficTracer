"""Classify whether a browser request should have packet-bearing transport."""

from __future__ import annotations

from ipaddress import ip_address
import re
from urllib.parse import urlsplit


NON_NETWORK_OBSERVATIONS = frozenset({
    "disk_cache",
    "service_worker",
    "prefetch_cache",
    "browser_internal",
    "local_endpoint",
    "failed_before_socket",
    "not_dispatched",
})


def request_network_observation(request) -> tuple[str, list[str]]:
    """Return the canonical network observation and its CDP evidence."""
    if request.from_service_worker:
        return "service_worker", ["cdp_from_service_worker"]
    if request.from_prefetch_cache:
        return "prefetch_cache", ["cdp_from_prefetch_cache"]
    if request.from_disk_cache:
        return "disk_cache", ["cdp_from_disk_cache"]
    if _is_local_endpoint(request):
        return "local_endpoint", ["cdp_local_endpoint"]
    if request.remote_ip or (
        request.connection_id is not None and request.connection_id > 0
    ):
        return "network", ["request_not_in_transport_index"]
    if request.failed and request.response_status <= 0:
        return "failed_before_socket", [
            "cdp_loading_failed",
            "cdp_transport_endpoint_absent",
        ]
    if (
        not request.failed
        and not request.canceled
        and request.response_status <= 0
        and not request.completion_timestamp
    ):
        return "not_dispatched", [
            "cdp_response_absent",
            "cdp_completion_absent",
            "cdp_transport_endpoint_absent",
        ]
    if request.connection_id == 0 and request.response_status > 0:
        return "browser_internal", [
            "cdp_connection_id_zero",
            "cdp_response_received",
        ]
    return "unknown", ["request_not_in_transport_index"]


def _is_local_endpoint(request) -> bool:
    host = urlsplit(request.url).hostname or ""
    if host.lower() == "localhost":
        return True
    for candidate in (host, request.remote_ip):
        if not candidate:
            continue
        try:
            if ip_address(candidate).is_loopback:
                return True
        except ValueError:
            continue
    return False


def request_can_have_transport(request) -> bool:
    """Reject cache/internal responses before any endpoint or host fallback."""
    observation, _ = request_network_observation(request)
    return observation not in NON_NETWORK_OBSERVATIONS


def flow_targets_loopback(flow) -> bool:
    """Return whether a correlated flow terminates at a loopback endpoint."""
    for candidate in (flow.pre_flow, flow.post_flow):
        if candidate is None:
            continue
        for value in (candidate.src_ip, candidate.dst_ip):
            try:
                if ip_address(value).is_loopback:
                    return True
            except ValueError:
                continue
    terminal_error = flow.terminal.error if flow.terminal else ""
    if "::1" in terminal_error:
        return True
    for value in re.findall(
        r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])",
        terminal_error,
    ):
        try:
            if ip_address(value).is_loopback:
                return True
        except ValueError:
            continue
    return False
