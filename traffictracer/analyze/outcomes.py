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
