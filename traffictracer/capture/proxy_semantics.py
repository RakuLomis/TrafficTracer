"""Capture-scoped runtime proxy semantics evidence.

The start/end snapshots detect configuration drift only.  Trace event references
remain authoritative for deciding which adapter and carrier handled a connection.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_runtime_semantics_artifact(start: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "source": {
            "component": "mihomo",
            "scope": "runtime_adapter",
            "configured": "accepted_configuration",
            "effective": "applied_defaults_and_normalization",
            "negotiated": "connection_specific_when_available",
            "observed": "connection_bound_trace_when_available",
        },
        "capture_time_authoritative": True,
        "ownership": {
            "rule": "trace_event_adapter_reference",
            "snapshot_role": "configuration_drift_check",
        },
        "started_at": _now(),
        "start": deepcopy(start),
        "end": None,
        "verification": {
            "state": "pending",
            "same_snapshot": None,
            "same_config_generation": None,
            "same_adapter_instance": None,
            "same_protocol": None,
            "same_behavior": None,
            "same_binary": None,
            "details": [],
        },
    }


def finish_runtime_semantics_artifact(
    artifact: dict[str, Any],
    end: dict[str, Any] | None,
    *,
    error: str = "",
) -> dict[str, Any]:
    result = deepcopy(artifact)
    result["finished_at"] = _now()
    if end is None:
        result["verification"] = {
            "state": "end_snapshot_unavailable",
            "same_snapshot": None,
            "same_config_generation": None,
            "same_adapter_instance": None,
            "same_protocol": None,
            "same_behavior": None,
            "same_binary": None,
            "details": [error or "runtime semantics end snapshot unavailable"],
        }
        return result

    result["end"] = deepcopy(end)
    start = result["start"]
    start_binary = start.get("build", {}).get("executable_sha256")
    end_binary = end.get("build", {}).get("executable_sha256")
    comparisons = {
        "same_snapshot": start.get("snapshot_id") == end.get("snapshot_id"),
        "same_config_generation": (
            start.get("config_generation") == end.get("config_generation")
        ),
        "same_adapter_instance": (
            start.get("adapter_instance_id") == end.get("adapter_instance_id")
        ),
        "same_protocol": start.get("protocol") == end.get("protocol"),
        "same_behavior": (
            start.get("behavior_fingerprint") == end.get("behavior_fingerprint")
        ),
        "same_binary": (
            start_binary == end_binary
            if start_binary and end_binary
            else None
        ),
    }
    details: list[str] = []
    if comparisons["same_binary"] is False:
        state = "core_binary_changed"
        details.append("running core binary changed during capture")
    elif not comparisons["same_protocol"] or not comparisons["same_behavior"]:
        state = "configuration_drift"
        details.append("effective proxy behavior changed during capture")
    elif not (
        comparisons["same_snapshot"]
        and comparisons["same_config_generation"]
        and comparisons["same_adapter_instance"]
    ):
        state = "adapter_replaced_same_behavior"
        details.append("runtime adapter was replaced with equivalent behavior")
    elif comparisons["same_binary"] is None:
        state = "binary_identity_unavailable"
        details.append("running core executable identity was unavailable")
    else:
        state = "passed"
    result["verification"] = {
        "state": state,
        **comparisons,
        "details": details,
    }
    return result


def runtime_semantics_summary(artifact: dict[str, Any]) -> dict[str, Any]:
    start = artifact["start"]
    summary = {
        "schema_version": artifact["schema_version"],
        "source": deepcopy(artifact["source"]),
        "snapshot_id": start["snapshot_id"],
        "config_generation": start["config_generation"],
        "adapter_instance_id": start["adapter_instance_id"],
        "protocol": start["protocol"],
        "behavior_fingerprint": start["behavior_fingerprint"],
        "coverage": deepcopy(start["coverage"]),
        "verification": deepcopy(artifact["verification"]),
    }
    return summary
