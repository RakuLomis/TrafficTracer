"""Evidence-bounded egress and terminal outcome semantics."""

from __future__ import annotations

from collections.abc import Mapping


NO_SOCKET_EGRESS_OUTCOMES = frozenset({
    "rejected",
    "rejected_drop",
    "internal_dns",
})

FAILED_TERMINAL_STATUSES = frozenset({
    "dial_error",
    "resolve_error",
    "canceled",
})

SHARED_CARRIER_PROTOCOLS = frozenset({
    "anytls",
    "hysteria",
    "hysteria2",
    "tuic",
})


def egress_outcome(record: Mapping[str, object]) -> str:
    value = record.get("egress_outcome")
    if isinstance(value, str) and value:
        return value
    egress = record.get("egress")
    if isinstance(egress, Mapping):
        value = egress.get("outcome")
        if isinstance(value, str):
            return value
    return ""


def terminal_payload(record: Mapping[str, object]) -> Mapping[str, object]:
    terminal = record.get("terminal")
    return terminal if isinstance(terminal, Mapping) else {}


def terminal_is_failure(record: Mapping[str, object]) -> bool:
    terminal = terminal_payload(record)
    status = str(terminal.get("status", ""))
    stage = str(terminal.get("stage", ""))
    error_class = str(terminal.get("error_class", ""))
    if status in FAILED_TERMINAL_STATUSES or status.endswith("_error"):
        return True
    if error_class and error_class not in {"policy_rejected"}:
        return True
    return bool(stage in {"resolve", "rule", "dial"} and terminal.get("error"))


def outcome_without_socket(value: object) -> bool:
    return isinstance(value, str) and value in NO_SOCKET_EGRESS_OUTCOMES


def record_without_socket(record: Mapping[str, object]) -> bool:
    return outcome_without_socket(egress_outcome(record))


def post_flow_disposition(
    record: Mapping[str, object],
    *,
    local_endpoint: bool = False,
) -> str:
    """Classify why a logical flow does or does not have a post-proxy tuple.

    The categories are mutually exclusive and use only persisted evidence.
    """
    if record.get("post_flow") is not None:
        return "with_post_flow"
    if local_endpoint:
        return "local_not_applicable"
    if record_without_socket(record):
        return "explicit_no_socket"
    if terminal_is_failure(record):
        return "failed_before_socket"
    return "unexpected_missing"


def egress_evidence_kind(
    record: Mapping[str, object],
    *,
    local_endpoint: bool = False,
) -> str:
    """Describe the strongest egress evidence without implying ownership."""
    binding_value = record.get("carrier_binding")
    binding = binding_value if isinstance(binding_value, Mapping) else {}
    post_value = record.get("post_flow")
    post_flow = post_value if isinstance(post_value, Mapping) else {}
    physical_paths = binding.get("physical_paths")
    has_physical_paths = bool(
        isinstance(physical_paths, (list, tuple)) and physical_paths
    )
    shared = bool(
        binding.get("mode") == "shared"
        or post_flow.get("shared")
    )
    if post_flow:
        return "shared_carrier" if shared else "exclusive_socket"
    if binding.get("carrier_id"):
        if has_physical_paths:
            return "shared_carrier" if shared else "exclusive_socket"
        return "carrier_path_unavailable"
    if local_endpoint:
        return "local_not_applicable"
    if record_without_socket(record):
        return "explicit_no_socket"
    if terminal_is_failure(record):
        return "failed_before_socket"

    selected_type = ""
    egress = record.get("egress")
    if isinstance(egress, Mapping):
        selected_type = str(egress.get("selected_type") or "")
    if not selected_type:
        selected_type = str(record.get("leaf_proxy_type") or "")
    normalized_type = selected_type.lower().replace("-", "").replace("_", "")
    outcome = egress_outcome(record)
    if not outcome and isinstance(egress, Mapping):
        outcome = str(egress.get("outcome") or "")
    if outcome == "proxy" and normalized_type in SHARED_CARRIER_PROTOCOLS:
        return "carrier_binding_unavailable"
    return "egress_unavailable"


def terminal_error_class(
    *,
    status: str,
    stage: str,
    error: str,
    explicit: str = "",
) -> tuple[str, str]:
    """Return a stable class and whether it was explicit or conservatively inferred."""
    if explicit:
        return explicit, "core_explicit"
    message = error.lower()
    if status == "rejected" or stage == "reject":
        return "policy_rejected", "legacy_inferred"
    if status == "canceled":
        return "canceled", "legacy_inferred"
    if status == "resolve_error" or any(
        token in message for token in ("find ip", "no such host", "dns")
    ):
        return "dns_resolution", "legacy_inferred"
    if "refused" in message:
        return "connection_refused", "legacy_inferred"
    if any(
        token in message
        for token in ("network is unreachable", "no route to host", "unreachable")
    ):
        return "network_unreachable", "legacy_inferred"
    if any(
        token in message
        for token in ("deadline exceeded", "timed out", "timeout")
    ):
        return "timeout", "legacy_inferred"
    if status == "dial_error" or stage == "dial":
        return "dial_failure", "legacy_inferred"
    if stage == "rule" and error:
        return "rule_failure", "legacy_inferred"
    if error:
        return "transport_failure", "legacy_inferred"
    return "", "unavailable"
