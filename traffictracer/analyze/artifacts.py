"""Persist UI-ready normalized Flow index and analysis summary artifacts."""

from __future__ import annotations

from collections import Counter
from ipaddress import ip_address
from dataclasses import dataclass
import json
import re
from pathlib import Path
from urllib.parse import urldefrag

from traffictracer.contracts import validate_flow
from traffictracer.models import CarrierBinding, FlowTuple
from traffictracer.session.atomic import write_json_atomic
from traffictracer.version import FLOW_SCHEMA_VERSION

from .activity import session_activity_outcomes
from .flow_index import FlowIndex, FlowMapping
from .mihomo_log import trace_snapshot_info
from .outcomes import (
    outcome_without_socket,
    post_flow_disposition, record_without_socket, terminal_error_class,
    terminal_is_failure,
)
from .consistency import validate_analysis_consistency
from .request_observation import NON_NETWORK_OBSERVATIONS


FLOW_INDEX_NAME = "flow-index.json"
SUMMARY_NAME = "summary.json"


@dataclass(frozen=True)
class AnalysisArtifacts:
    flow_index: Path
    summary: Path


def persist_analysis_artifacts(
    session_dir: str | Path,
    session_id: str,
    *,
    output_dir: str | Path | None = None,
) -> AnalysisArtifacts:
    session = Path(session_dir)
    mappings = _load_mappings(session)
    trace_snapshot = _trace_snapshot_summary(session)

    pre_counts = Counter(mapping.pre_flow.key for mapping in mappings)
    outer_counts = Counter(
        mapping.outer_conn_id for mapping in mappings if mapping.outer_conn_id
    )
    items = _core_flow_items(mappings, session_id, pre_counts, outer_counts)
    results = Path(output_dir) if output_dir is not None else session / "results"
    request_records, connection_records, generation_id = _v2_records(results)
    _enrich_core_flow_items(items, connection_records)
    for item in items:
        validate_flow(item)
    pcap_payload = _read_index(results / "pcap-index-v1.json")
    consistency = validate_analysis_consistency(
        request_records,
        connection_records,
        items,
        pcap_payload=pcap_payload,
        legacy_payload=_read_index(results / "correlation.json"),
        generation_id=generation_id,
    )

    error_ids = {
        mapping.connection_id for mapping in mappings if mapping.error
    }
    error_count = len(error_ids)
    local_connection_ids = _local_connection_ids(request_records, connection_records)
    local_core_ids = _local_core_ids(
        connection_records, items, local_connection_ids,
    )
    local_core_ids.update(
        mapping.connection_id for mapping in mappings
        if _mapping_targets_loopback(mapping)
    )
    _annotate_core_semantics(items, connection_records, local_core_ids)
    error_classes = Counter(
        _mapping_error_class(mapping) for mapping in mappings
        if mapping.error and mapping.connection_id not in local_core_ids
    )
    warnings = _warnings(
        items, pre_counts, error_ids, local_core_ids, error_classes,
    )
    warnings.extend(_quality_warnings(
        request_records, connection_records, pcap_payload, _target_url(session),
    ))
    coverage_failures = sum(
        isinstance(context.get("packet_coverage"), dict)
        and context["packet_coverage"].get("status") != "passed"
        for context in _capture_contexts(session)
    )
    if coverage_failures:
        warnings.extend({
            "code": "PACKET_CAPTURE_INCOMPLETE", "count": coverage_failures,
            "message": "Recorded packet lifecycle coverage did not pass; reanalysis cannot repair missing capture evidence.",
            "scope": scope, "severity": "error", "affects_page_quality": True,
        } for scope in ("page_attributed", "capture_global"))
    match_counts = Counter(item["match"]["status"] for item in items)
    protocol_counts = Counter(item["protocol"] for item in items)
    quality = analysis_quality(
        request_records, connection_records, pcap_payload, items,
        len(error_ids - local_core_ids), local_core_ids,
    )
    index_payload = {
        "schema_version": FLOW_SCHEMA_VERSION,
        "session_id": session_id,
        "pagination": {
            "total": len(items),
            "default_limit": 100,
            "max_limit": 1000,
        },
        "items": items,
    }
    playback = _playback_summary(session)
    playback_outcome = (
        _playback_scenario_outcome(playback)
        if playback is not None else None
    )
    navigation_outcome, resource_health, activity_outcome = (
        session_activity_outcomes(session, playback_outcome)
    )
    summary_payload = {
        "schema_version": FLOW_SCHEMA_VERSION,
        "session_id": session_id,
        "total_flows": len(items),
        "protocol_counts": dict(sorted(protocol_counts.items())),
        "match_counts": dict(sorted(match_counts.items())),
        "shared_flows": sum(bool(item["shared"]) for item in items),
        "missing_post_flows": sum(item["post_flow"] is None for item in items),
        "duplicate_pre_flow_keys": sum(count > 1 for count in pre_counts.values()),
        "error_flows": error_count,
        "warnings": warnings,
        "consistency": consistency,
        # This remains the selected page's quality for backward compatibility.
        # Capture-global diagnostics are reported separately below.
        "quality_state": _quality_state(
            consistency, warnings, scope="page_attributed",
        ),
        "capture_global_quality_state": _quality_state(
            consistency, warnings, scope="capture_global",
        ),
        "quality": quality,
        "analysis_integrity": {
            "page_attributed": {
                "state": _analysis_integrity_state(
                    consistency, warnings, scope="page_attributed",
                ),
            },
            "capture_global": {
                "state": _analysis_integrity_state(
                    consistency, warnings, scope="capture_global",
                ),
            },
        },
        "network_outcome": _network_outcome_summary(
            request_records, connection_records, items, local_core_ids,
        ),
        "browser_request_failures": _browser_request_failure_summary(
            request_records,
        ),
        "trace_snapshot": trace_snapshot,
        "storage": _storage_summary(session, results),
        "carrier_bindings": _carrier_binding_summary(items),
        "proxy_protocol": _capture_protocol_summary(session),
        "packet_coverage": [context["packet_coverage"] for context in _capture_contexts(session)
                            if isinstance(context.get("packet_coverage"), dict)],
        "inbound": _capture_inbound_summary(session, items),
        "navigation_outcome": navigation_outcome,
        "resource_health": resource_health,
        "activity_outcome": activity_outcome,
    }
    if playback is not None:
        summary_payload["playback"] = playback
        summary_payload["scenario_outcome"] = playback_outcome
    summary_payload["coverage"] = layered_coverage(
        request_records,
        connection_records,
        items,
        local_core_ids=local_core_ids,
    )
    summary_payload["missing_post_flows"] = summary_payload["coverage"][
        "capture_global"
    ]["core_logical_flows"]["missing_post_flow"]
    summary_payload["match_method_counts"] = dict(sorted(
        Counter(
            item["match"]["method"]
            for item in connection_records
        ).items()
    ))
    summary_payload["coverage_source"] = (
        "v2_indexes" if generation_id else "core_only"
    )
    if generation_id:
        index_payload["analysis_generation_id"] = generation_id
        summary_payload["analysis_generation_id"] = generation_id

    results.mkdir(parents=True, exist_ok=True, mode=0o700)
    flow_index_path = results / FLOW_INDEX_NAME
    summary_path = results / SUMMARY_NAME
    write_json_atomic(flow_index_path, index_payload)
    write_json_atomic(summary_path, summary_payload)
    return AnalysisArtifacts(flow_index_path, summary_path)


def layered_coverage(
    request_records: list[dict],
    connection_records: list[dict],
    core_flow_records: list[dict] | None = None,
    *,
    local_core_ids: set[str] | None = None,
) -> dict:
    """Recompute conservative layer-specific coverage from persisted indexes."""
    browser = _request_partition(request_records)
    page_connections, background_connections = _scoped_connection_records(
        connection_records,
    )
    transport = _partition(
        record.get("match", {}).get("status", "unmatched")
        for record in page_connections
    )
    background_transport = _partition(
        record.get("match", {}).get("status", "unmatched")
        for record in background_connections
    )
    reasons: Counter[str] = Counter()
    for record in request_records:
        attribution = record.get("attribution", {})
        if (
            attribution.get("status") != "matched"
            and record.get("network_observation")
            in {None, "network", "unknown"}
        ):
            reasons[_normalized_reason(
                attribution.get("unmatched_reason"),
                "request_unmatched",
            )] += 1
    for record in page_connections:
        match = record.get("match", {})
        if match.get("status") != "matched":
            reasons[_normalized_reason(
                match.get("unmatched_reason"),
                "connection_unmatched",
            )] += 1

    page_reasons = reasons.copy()
    page_logical_records = [
        record for record in page_connections
        if record.get("post_flow") is not None
        or bool(record.get("mihomo_connection_id"))
        or record.get("terminal") is not None
        or _egress_without_socket(record)
    ]
    local_connection_ids = _local_connection_ids(request_records, connection_records)
    page_core = _core_coverage(
        page_logical_records, page_reasons,
        not_applicable_ids=local_connection_ids,
        id_field="connection_id",
    )
    core_records = (
        core_flow_records
        if core_flow_records is not None
        else connection_records
    )
    global_reasons: Counter[str] = Counter()
    local_core_ids = (local_core_ids or set()) | _local_core_ids(
        connection_records, core_records, local_connection_ids,
    )
    global_core = _core_coverage(
        core_records, global_reasons,
        not_applicable_ids=local_core_ids,
        id_field="conn_id",
    )
    attribution_scopes = Counter(
        record.get("attribution_scope", "capture_unattributed")
        for record in core_records
    )
    # Preserve the flattened v1 counters for legacy readers. New consumers
    # must use the explicit page_attributed/capture_global scopes below.
    reasons.update(global_reasons)
    coverage = {
        "browser_requests": browser,
        "transport_connections": transport,
        "core_logical_flows": global_core,
        "page_attributed": {
            "browser_requests": browser,
            "transport_connections": transport,
            "logical_flows": page_core,
            "unmatched_reasons": dict(sorted(page_reasons.items())),
        },
        "capture_global": {
            "core_logical_flows": global_core,
            "browser_background_transport_connections": background_transport,
            "attribution_scopes": dict(sorted(attribution_scopes.items())),
            "unmatched_reasons": dict(sorted(global_reasons.items())),
        },
        "unmatched_reasons": dict(sorted(reasons.items())),
    }
    _assert_coverage_conservation(coverage)
    return coverage


def _core_coverage(
    records: list[dict],
    reasons: Counter[str],
    *,
    not_applicable_ids: set[str] | None = None,
    id_field: str = "connection_id",
) -> dict:
    counts = Counter()
    local_ids = not_applicable_ids or set()
    for record in records:
        disposition = post_flow_disposition(
            record, local_endpoint=record.get(id_field) in local_ids,
        )
        counts[disposition] += 1
        if disposition == "unexpected_missing" and _capture_tail_unattributed(record):
            counts["capture_tail_unattributed"] += 1
    unexplained_missing = (
        counts["unexpected_missing"] - counts["capture_tail_unattributed"]
    )
    if unexplained_missing:
        reasons["missing_post_flow"] += unexplained_missing
    if counts["capture_tail_unattributed"]:
        reasons["capture_tail_unattributed"] += counts["capture_tail_unattributed"]
    if counts["failed_before_socket"]:
        reasons["failed_before_socket"] += counts["failed_before_socket"]
    if counts["local_not_applicable"]:
        reasons["local_endpoint_not_applicable"] += counts["local_not_applicable"]
    coverage = {
        "total": len(records),
        "with_post_flow": counts["with_post_flow"],
        "shared": sum(bool(record.get("shared")) for record in records),
        "missing_post_flow": counts["unexpected_missing"],
        "explicit_no_socket": counts["explicit_no_socket"],
        "failed_before_socket": counts["failed_before_socket"],
        "local_not_applicable": counts["local_not_applicable"],
        "unexpected_missing": counts["unexpected_missing"],
    }
    if counts["capture_tail_unattributed"]:
        coverage["capture_tail_unattributed"] = counts["capture_tail_unattributed"]
    # Backward-compatible aliases retained for older UI readers.
    if counts["local_not_applicable"]:
        coverage["not_applicable_local_endpoint"] = counts["local_not_applicable"]
    if counts["explicit_no_socket"]:
        coverage["not_applicable_outcome"] = counts["explicit_no_socket"]
    return coverage


def _partition(statuses) -> dict:
    counts = Counter({"matched": 0, "ambiguous": 0, "unmatched": 0})
    for status in statuses:
        normalized = (
            status if status in {"matched", "ambiguous", "unmatched"}
            else "unmatched"
        )
        counts[normalized] += 1
    return {"total": sum(counts.values()), **dict(counts)}


def _request_partition(records: list[dict]) -> dict:
    non_network = NON_NETWORK_OBSERVATIONS
    counts = Counter({
        "matched": 0, "ambiguous": 0, "unmatched": 0, "non_network": 0,
    })
    for record in records:
        if record.get("network_observation") in non_network:
            counts["non_network"] += 1
            continue
        status = record.get("attribution", {}).get("status", "unmatched")
        counts[
            status if status in {"matched", "ambiguous", "unmatched"}
            else "unmatched"
        ] += 1
    return {"total": sum(counts.values()), **dict(counts)}


def _assert_coverage_conservation(coverage: dict) -> None:
    for name in ("browser_requests", "transport_connections"):
        partition = coverage[name]
        keys = ["matched", "ambiguous", "unmatched"]
        if name == "browser_requests":
            keys.append("non_network")
        accounted = sum(partition[key] for key in keys)
        if accounted != partition["total"]:
            raise ValueError(f"{name} coverage does not conserve its total")
    core = coverage["core_logical_flows"]
    accounted_core = (
        core["with_post_flow"]
        + core["explicit_no_socket"]
        + core["failed_before_socket"]
        + core["local_not_applicable"]
        + core["unexpected_missing"]
    )
    if accounted_core != core["total"]:
        raise ValueError("core logical flow coverage does not conserve its total")
    if core["shared"] > core["total"]:
        raise ValueError("shared core logical flow count exceeds total")
    scopes = coverage["capture_global"].get("attribution_scopes", {})
    if sum(scopes.values()) != core["total"]:
        raise ValueError("capture-global attribution scopes do not conserve total")


def _normalized_reason(value: object, fallback: str) -> str:
    import re

    text = value if isinstance(value, str) and value else fallback
    normalized = re.sub(r"[^a-z0-9_]+", "_", text.lower()).strip("_")
    return normalized or fallback


def _v2_records(results: Path) -> tuple[list[dict], list[dict], str]:
    request_payload = _read_index(results / "request-index-v2.json")
    connection_payload = _read_index(results / "connection-index-v2.json")
    request_generation = request_payload.get("analysis_generation_id", "")
    connection_generation = connection_payload.get("analysis_generation_id", "")
    if request_generation != connection_generation:
        raise ValueError("request and connection indexes use different generations")
    return (
        list(request_payload.get("items", [])),
        list(connection_payload.get("items", [])),
        request_generation,
    )


def _enrich_core_flow_items(
    items: list[dict],
    connection_records: list[dict],
) -> None:
    """Attach canonical browser attribution through Mihomo connection IDs."""
    by_mihomo: dict[str, dict[str, set[str]]] = {}
    for connection in connection_records:
        mihomo_id = connection.get("mihomo_connection_id")
        if not mihomo_id or connection.get("match", {}).get("status") != "matched":
            continue
        attribution = by_mihomo.setdefault(mihomo_id, {
            "request_ids": set(),
            "connection_ids": set(),
            "urls": set(),
            "primary_urls": set(),
        })
        attribution["request_ids"].update(connection.get("request_ids", []))
        attribution["connection_ids"].add(connection["connection_id"])
        attribution["urls"].update(connection.get("urls", []))
        if connection.get("primary_url"):
            attribution["primary_urls"].add(connection["primary_url"])

    for item in items:
        attribution = by_mihomo.get(item.get("conn_id", ""))
        if not attribution:
            continue
        item["request_ids"] = sorted(attribution["request_ids"])
        item["connection_ids"] = sorted(attribution["connection_ids"])
        item["urls"] = sorted(attribution["urls"])
        primary_urls = sorted(attribution["primary_urls"] & attribution["urls"])
        if not primary_urls and item["urls"]:
            primary_urls = [item["urls"][0]]
        if primary_urls:
            item["primary_url"] = primary_urls[0]
            item["url"] = primary_urls[0]


def _annotate_core_semantics(
    items: list[dict],
    connection_records: list[dict],
    local_core_ids: set[str],
) -> None:
    browser_core_ids = {
        record.get("mihomo_connection_id") for record in connection_records
        if record.get("mihomo_connection_id")
        and record.get("netlog_source_id") is not None
    }
    for item in items:
        conn_id = item.get("conn_id")
        if conn_id in local_core_ids:
            scope, evidence = "local_internal", ["local_endpoint_evidence"]
        elif item.get("request_ids") or item.get("urls"):
            scope, evidence = "page_attributed", ["request_connection_lineage"]
        elif conn_id in browser_core_ids:
            scope, evidence = "browser_background", ["netlog_transport"]
        else:
            scope, evidence = "capture_unattributed", ["mihomo_trace_only"]
        item["attribution_scope"] = scope
        item["attribution_evidence"] = evidence
        item["post_flow_disposition"] = post_flow_disposition(
            item, local_endpoint=conn_id in local_core_ids,
        )


def _read_index(path: Path) -> dict:
    if not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"analysis index must be an object: {path}")
    return payload


def _carrier_binding_summary(items: list[dict]) -> dict:
    proxy_items = [item for item in items if item.get("egress_outcome") == "proxy"]
    bindings = [
        item["carrier_binding"]
        for item in proxy_items
        if isinstance(item.get("carrier_binding"), dict)
        and item["carrier_binding"].get("carrier_id")
    ]
    fan_out = Counter(
        binding["carrier_id"]
        for binding in bindings
        if binding.get("mode") == "shared"
    )
    physical_carriers = {
        binding["carrier_id"]
        for binding in bindings
        if binding.get("physical_paths")
    }
    return {
        "logical_proxy_flows": len(proxy_items),
        "bound_logical_flows": len(bindings),
        "missing_binding": len(proxy_items) - len(bindings),
        "exclusive_socket_count": sum(
            binding.get("mode") == "exclusive" for binding in bindings
        ),
        "shared_bound_logical_flows": sum(
            binding.get("mode") == "shared" for binding in bindings
        ),
        "shared_carrier_count": len(fan_out),
        "shared_carrier_max_fan_out": max(fan_out.values(), default=0),
        "shared_carrier_fan_out": dict(sorted(fan_out.items())),
        "physical_carriers_observed": len(physical_carriers),
    }


def _capture_contexts(session: Path) -> list[dict]:
    paths = [session / "raw" / "capture-context.json"]
    paths.extend(sorted((session / "logs").glob("capture_context_*.json")))
    contexts = []
    for path in paths:
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict):
            contexts.append(payload)
    return contexts


def _capture_protocol_summary(session: Path) -> dict:
    snapshots = [
        context.get("proxy_protocol", {})
        for context in _capture_contexts(session)
        if isinstance(context.get("proxy_protocol"), dict)
    ]
    if not snapshots:
        return {
            "expected_protocol": "",
            "observed_protocols": [],
            "consistency": "unavailable",
        }
    latest = snapshots[-1]
    runtime = latest.get("runtime_observation", {})
    return {
        "mode": latest.get("mode", ""),
        "expected_protocol": latest.get("expected_protocol", ""),
        "selected_protocols": latest.get("protocols", []),
        "selection_group": latest.get("selection_group", ""),
        "selected_scope": latest.get("selected_scope", {}),
        "inventory_protocols": latest.get("inventory_protocols", []),
        "observed_protocols": runtime.get("protocols", []),
        "consistency": runtime.get("consistency", "not_observed"),
        "proxy_dial_events": runtime.get("proxy_dial_events", 0),
    }


def _capture_inbound_summary(session: Path, items: list[dict]) -> dict:
    contexts = _capture_contexts(session)
    inbound = contexts[-1].get("inbound", {}) if contexts else {}
    configured = dict(inbound) if isinstance(inbound, dict) else {}
    expected = str(configured.get("expected_core_name", ""))
    observed = Counter(
        str(item.get("inbound_name", ""))
        for item in items if item.get("inbound_name")
    )
    mismatched = sum(
        count for name, count in observed.items() if expected and name != expected
    )
    loopback = sum(_record_targets_loopback(item) for item in items)
    configured.update({
        "observed_names": dict(sorted(observed.items())),
        "mismatched_flows": mismatched,
        "loopback_flows": loopback,
        "consistency": (
            "not_observed" if not observed
            else "match" if mismatched == 0 and loopback == 0
            else "match_with_local" if mismatched == 0
            else "mismatch"
        ),
    })
    return configured


def core_flow_records(
    session_dir: str | Path,
    session_id: str,
) -> list[dict]:
    """Build the same normalized core records used by flow-index.json."""
    mappings = _load_mappings(Path(session_dir))
    pre_counts = Counter(mapping.pre_flow.key for mapping in mappings)
    outer_counts = Counter(
        mapping.outer_conn_id for mapping in mappings if mapping.outer_conn_id
    )
    return _core_flow_items(mappings, session_id, pre_counts, outer_counts)


def _tree_bytes(root: Path, predicate=None) -> int:
    if not root.exists():
        return 0
    total = 0
    paths = [root] if root.is_file() else root.rglob("*")
    for path in paths:
        if not path.is_file() or (predicate is not None and not predicate(path)):
            continue
        try:
            total += path.stat().st_size
        except OSError:
            continue
    return total


def _storage_summary(session: Path, results: Path) -> dict:
    raw = session / "raw"
    capture_roots = (
        [raw]
        if raw.is_dir()
        else [session / "logs", session / "captures"]
    )
    capture_bytes = sum(_tree_bytes(root) for root in capture_roots)
    packet_bytes = sum(
        _tree_bytes(root, lambda path: path.suffix == ".pcap")
        for root in capture_roots
    )
    netlog_bytes = sum(
        _tree_bytes(root, lambda path: path.name.startswith("netlog"))
        for root in capture_roots
    )
    trace_bytes = sum(
        _tree_bytes(
            root,
            lambda path: "mihomo-trace" in path.name.replace("_", "-"),
        )
        for root in capture_roots
    )
    snapshot_bytes = _tree_bytes(raw / "trace-input", lambda path: path.name in {"trace.jsonl", "trace.jsonl.gz"})
    archive_bytes = _tree_bytes(raw / "trace-archive", lambda path: path.name == "journal.jsonl.gz")
    snapshot_logical_bytes = None
    snapshot_meta = raw / "trace-input" / "snapshot.json"
    if snapshot_meta.is_file():
        metadata = json.loads(snapshot_meta.read_text())
        snapshot_logical_bytes = metadata.get("size_bytes")
    return {
        "capture_bytes": capture_bytes,
        "raw_packet_capture_bytes": packet_bytes,
        "netlog_bytes": netlog_bytes,
        "mihomo_trace_bytes": trace_bytes,
        "trace_snapshot_bytes": snapshot_bytes,
        "trace_snapshot_logical_bytes": snapshot_logical_bytes,
        "trace_archive_bytes": archive_bytes,
        "trace_snapshot_compression_ratio": (
            snapshot_bytes / snapshot_logical_bytes
            if isinstance(snapshot_logical_bytes, int) and snapshot_logical_bytes > 0 else None
        ),
        "capture_metadata_bytes": max(
            0, capture_bytes - packet_bytes - netlog_bytes - trace_bytes - snapshot_bytes - archive_bytes
        ),
        "analysis_result_bytes_before_summary": _tree_bytes(results),
        "compression": "trace_gzip" if (raw / "trace-input/trace.jsonl.gz").is_file() or archive_bytes else "none",
    }


def _trace_paths(session: Path) -> list[Path]:
    from traffictracer.capture.trace_snapshot import analysis_trace_path
    raw_trace = analysis_trace_path(session / "raw")
    return (
        [raw_trace]
        if raw_trace.is_file()
        else sorted((session / "logs").glob("mihomo_trace_*.jsonl"))
    )


def _trace_snapshot_summary(session: Path) -> dict:
    traces = [trace_snapshot_info(str(path)) for path in _trace_paths(session)]
    sources = {item["source"] for item in traces}
    late_types = Counter()
    for item in traces:
        late_types.update(item.get("late_event_types", {}))
    return {
        "source": sources.pop() if len(sources) == 1 else "mixed",
        "trace_count": len(traces),
        "late_event_count": sum(item["late_event_count"] for item in traces),
        "late_event_types": dict(sorted(late_types.items())),
        "causal_tail_event_count": sum(
            item.get("causal_tail_event_count", 0) for item in traces
        ),
        "max_late_delay_ms": max(
            (item.get("max_late_delay_ms", 0.0) for item in traces), default=0.0,
        ),
        "traces": traces,
    }


def _load_mappings(session: Path) -> list[FlowMapping]:
    mappings: list[FlowMapping] = []
    trace_paths = _trace_paths(session)
    for trace_path in trace_paths:
        snapshot = trace_snapshot_info(str(trace_path))
        causal_tail = set(snapshot.get("causal_tail_event_seqs", []))
        mappings.extend(
            FlowIndex.from_log(
                str(trace_path), snapshot["cutoff_event_seq"], causal_tail
            ).mappings
        )
    return [
        mapping
        for mapping in mappings
        if mapping.pre_flow.complete and bool(mapping.pre_flow.key)
    ]


def _core_flow_items(
    mappings: list[FlowMapping],
    session_id: str,
    pre_counts: Counter[str],
    outer_counts: Counter[str],
) -> list[dict]:
    items = [
        _flow_item(mapping, session_id, pre_counts, outer_counts)
        for mapping in sorted(
            mappings,
            key=lambda item: (
                item.pre_flow.key,
                item.pre_flow.network,
                item.connection_id,
            ),
        )
    ]
    for item in items:
        validate_flow(item)
    return items


def _flow_item(
    mapping: FlowMapping,
    session_id: str,
    pre_counts: Counter[str],
    outer_counts: Counter[str],
) -> dict:
    candidate_count = pre_counts[mapping.pre_flow.key]
    usable_post = (
        mapping.post_flow
        if mapping.post_flow is not None and mapping.post_flow.complete
        else None
    )
    shared = bool(
        mapping.pre_flow.shared
        or (usable_post is not None and usable_post.shared)
        or (
            mapping.outer_conn_id
            and outer_counts[mapping.outer_conn_id] > 1
        )
    )
    if usable_post is None and _outcome_without_socket(mapping.egress_outcome):
        match_status = "matched"
        confidence = 1.0
        reason = f"explicit {mapping.egress_outcome} egress has no outbound socket"
    elif usable_post is None:
        match_status = "unmatched"
        confidence = 0.0
        reason = "no complete post-proxy flow"
    elif candidate_count > 1:
        match_status = "matched"
        confidence = 1.0
        reason = "native connection identity preserves reused pre-proxy tuple mapping"
    else:
        match_status = "matched"
        confidence = 1.0
        reason = "exact normalized pre-proxy tuple"

    terminal = None
    if mapping.status not in {"", "mapped", "pending"} or mapping.error:
        terminal = {
            "status": mapping.status or "unknown",
            "stage": mapping.stage,
            "error": mapping.error,
            "error_class": mapping.error_class,
            "error_class_source": mapping.error_class_source,
        }

    item = {
        "schema_version": FLOW_SCHEMA_VERSION,
        "session_id": session_id,
        "flow_id": f"{_network(mapping.pre_flow.network)}:{mapping.connection_id}",
        "protocol": _network(mapping.pre_flow.network),
        "pre_flow": _tuple_payload(mapping.pre_flow, "pre_proxy"),
        "post_flow": (
            _tuple_payload(usable_post, "post_proxy")
            if usable_post is not None
            else None
        ),
        "shared": shared,
        "match": {
            "status": match_status,
            "confidence": confidence,
            "candidate_count": candidate_count,
            "reason": reason,
        },
        "request_ids": [],
        "conn_id": mapping.connection_id,
        "terminal": terminal,
        "attribution_scope": "capture_unattributed",
        "attribution_evidence": ["mihomo_trace_only"],
    }
    if mapping.outer_conn_id:
        item["outer_conn_id"] = mapping.outer_conn_id
    if mapping.carrier_binding is not None:
        item["carrier_binding"] = _carrier_binding_payload(mapping.carrier_binding)
    if mapping.egress_outcome:
        item["egress_outcome"] = mapping.egress_outcome
    if mapping.inbound_name:
        item["inbound_name"] = mapping.inbound_name
    item["post_flow_disposition"] = post_flow_disposition(item)
    if mapping.carrier_binding is not None:
        item["carrier_state"] = (
            "shared_bound"
            if mapping.carrier_binding.mode == "shared"
            else "exclusive_bound"
        )
    elif _outcome_without_socket(mapping.egress_outcome):
        item["carrier_state"] = "not_applicable"
    elif item["post_flow_disposition"] == "failed_before_socket":
        item["carrier_state"] = "failed_before_carrier"
    else:
        item["carrier_state"] = "observation_missing"
    return item


def _tuple_payload(flow: FlowTuple, scope: str) -> dict:
    payload = {
        "network": _network(flow.network),
        "src_ip": flow.src_ip,
        "src_port": flow.src_port,
        "dst_ip": flow.dst_ip,
        "dst_port": flow.dst_port,
        "complete": flow.complete,
        "source": flow.source or "mihomo",
        "scope": scope,
        "shared": flow.shared,
    }
    if flow.dst_host:
        payload["dst_host"] = flow.dst_host
    return payload


def _carrier_binding_payload(binding: CarrierBinding) -> dict:
    paths = [
        _tuple_payload(path, "post_proxy")
        for path in binding.paths
        if path.complete
    ]
    status = "shared_bound" if binding.mode == "shared" else "exclusive_bound"
    payload = {
        "carrier_id": binding.carrier_id,
        "status": status,
        "mode": binding.mode,
        "relation": binding.relation or "observed",
        "generation": binding.generation,
        "protocol": binding.protocol or "unknown",
        "physical_paths": paths,
    }
    return payload


def _network(value: str) -> str:
    lowered = value.lower()
    if lowered.startswith("tcp"):
        return "tcp"
    if lowered.startswith("udp"):
        return "udp"
    raise ValueError(f"unsupported normalized flow network: {value}")


def _capture_tail_unattributed(record: dict) -> bool:
    if record.get("post_flow_disposition") != "unexpected_missing":
        return False
    if record.get("attribution_scope") != "capture_unattributed":
        return False
    if record.get("request_ids") or record.get("urls"):
        return False
    terminal = record.get("terminal")
    return not isinstance(terminal, dict) or not any(
        terminal.get(field) for field in ("status", "stage", "error")
    )


def _warnings(
    items: list[dict],
    pre_counts: Counter[str],
    error_ids: set[str],
    local_core_ids: set[str],
    error_classes: Counter[str] | None = None,
) -> list[dict]:
    """Build diagnostics for all Mihomo flows observed during the capture."""
    warnings: list[dict] = []
    duplicate_keys = sorted(key for key, count in pre_counts.items() if count > 1)
    if duplicate_keys:
        warning = _warning(
            "DUPLICATE_PRE_FLOW",
            len(duplicate_keys),
            "Some pre-proxy tuples map to multiple logical flows.",
            scope="capture_global",
        )
        warning["keys"] = duplicate_keys
        warnings.append(warning)
    shared_count = sum(bool(item["shared"]) for item in items)
    if shared_count:
        warnings.append(_warning(
            "SHARED_OUTER_FLOW",
            shared_count,
            "Shared outer flows are not exclusive one-to-one mappings.",
            scope="capture_global",
            severity="info",
        ))
    dispositions = Counter(item["post_flow_disposition"] for item in items)
    tail_incomplete = sum(_capture_tail_unattributed(item) for item in items)
    unexplained_missing = dispositions["unexpected_missing"] - tail_incomplete
    if unexplained_missing:
        warnings.append(_warning(
            "POST_FLOW_UNAVAILABLE",
            unexplained_missing,
            "Some capture-global logical flows have no explained post-proxy outcome.",
            scope="capture_global",
        ))
    if tail_incomplete:
        warnings.append(_warning(
            "CAPTURE_TAIL_UNATTRIBUTED",
            tail_incomplete,
            "Unattributed background flows remained incomplete at the trace boundary.",
            scope="capture_global", severity="info",
        ))
    if dispositions["explicit_no_socket"]:
        warnings.append(_warning(
            "EGRESS_OUTCOME_NOT_APPLICABLE",
            dispositions["explicit_no_socket"],
            "Explicit no-socket egress outcomes have no applicable post-proxy flow.",
            scope="capture_global", severity="info",
        ))
    if dispositions["failed_before_socket"]:
        warnings.append(_warning(
            "EGRESS_FAILED_BEFORE_SOCKET",
            dispositions["failed_before_socket"],
            "Observed network failures ended before an outbound socket was created.",
            scope="capture_global", severity="info",
        ))
    if dispositions["local_not_applicable"]:
        warnings.append(_warning(
            "LOCAL_ENDPOINT_UNAVAILABLE",
            dispositions["local_not_applicable"],
            "Local endpoint probes have no applicable post-proxy flow.",
            scope="capture_global", severity="info",
        ))
    actionable_error_count = len(error_ids - local_core_ids)
    if actionable_error_count:
        warnings.append(_warning(
            "FLOW_ERRORS",
            actionable_error_count,
            "Some capture-global logical flows ended with a tracing error.",
            scope="capture_global",
            severity="info",
        ))
    classified = error_classes or Counter()
    for code, message in (
        ("timeout", "Connections timed out before establishment."),
        ("dns_resolution", "Mihomo could not resolve one or more flow destinations."),
    ):
        if classified[code]:
            warnings.append(_warning(
                code.upper(), classified[code], message,
                scope="capture_global",
                severity="info",
            ))
    return warnings


def analysis_quality(
    request_records: list[dict],
    connection_records: list[dict],
    pcap_payload: dict,
    core_flow_records: list[dict] | None = None,
    core_error_count: int = 0,
    local_core_ids: set[str] | None = None,
) -> dict:
    """Return conservative, denominator-preserving scoped quality metrics."""
    browser = _request_partition(request_records)
    eligible_requests = browser["total"] - browser["non_network"]
    page_connections, background_connections = _scoped_connection_records(
        connection_records,
    )
    local_connection_ids = _local_connection_ids(request_records, connection_records)
    applicable_connections = [
        record for record in page_connections
        if record.get("connection_id") not in local_connection_ids
    ]
    socket_applicable_connections = [
        record for record in applicable_connections
        if not _egress_without_socket(record)
    ]
    not_applicable_outcome = (
        len(applicable_connections) - len(socket_applicable_connections)
    )
    transport = _partition(
        record.get("match", {}).get("status", "unmatched")
        for record in page_connections
    )

    established = sum(
        record.get("post_flow") is not None
        for record in socket_applicable_connections
    )
    failed_before_socket = sum(
        record.get("post_flow") is None
        and terminal_is_failure(record)
        for record in socket_applicable_connections
    )
    unavailable = (
        len(socket_applicable_connections) - established - failed_before_socket
    )

    split_mode = pcap_payload.get("split_mode", "none")
    pcap_connections = _scoped_pcap_connections(
        pcap_payload, page_connections, connection_records,
    )
    post_applicable_pcaps = [
        item for item in pcap_connections
        if item.get("post_proxy", {}).get("status")
        not in {"not_applicable", "not_requested"}
    ]
    post_not_applicable = sum(
        item.get("post_proxy", {}).get("status") == "not_applicable"
        for item in pcap_connections
    )
    post_not_requested = sum(
        item.get("post_proxy", {}).get("status") == "not_requested"
        for item in pcap_connections
    )
    pre_success = sum(
        item.get("pre_proxy", {}).get("status") == "success"
        for item in pcap_connections
    )
    post_success = sum(
        item.get("post_proxy", {}).get("status") == "success"
        for item in post_applicable_pcaps
    )
    complete_pairs = sum(
        item.get("pre_proxy", {}).get("status") == "success"
        and item.get("post_proxy", {}).get("status") == "success"
        for item in post_applicable_pcaps
    )
    page_quality = {
        "request_attribution": {
            "eligible": eligible_requests,
            "matched": browser["matched"],
            "ambiguous": browser["ambiguous"],
            "unmatched": browser["unmatched"],
        },
        "transport_correlation": transport,
        "egress_establishment": {
            "total": len(page_connections),
            "established": established,
            "failed_before_socket": failed_before_socket,
            "unavailable": unavailable,
        },
        "pcap_extraction": {
            "requested": split_mode == "unique_connections",
            "total": len(pcap_connections),
            "pre_success": pre_success,
            "post_applicable": len(post_applicable_pcaps),
            "post_success": post_success,
            "complete_pairs": complete_pairs,
            "post_not_applicable": post_not_applicable,
            "post_not_requested": post_not_requested,
        },
    }
    if not_applicable_outcome:
        page_quality["egress_establishment"][
            "not_applicable_outcome"
        ] = not_applicable_outcome
    if local_connection_ids:
        page_quality["egress_establishment"][
            "not_applicable_local_endpoint"
        ] = len(local_connection_ids)
    core_records = core_flow_records or []
    global_local_ids = local_core_ids or set()
    global_logical_flows = _core_coverage(
        core_records, Counter(), not_applicable_ids=global_local_ids,
        id_field="conn_id",
    )
    global_logical_flows["errors"] = core_error_count
    capture_global = {
        "logical_flows": global_logical_flows,
        "browser_background": {
            "transport_correlation": _partition(
                record.get("match", {}).get("status", "unmatched")
                for record in background_connections
            ),
            "pcap_extraction": _pcap_quality(
                (
                    _scoped_pcap_connections(
                        pcap_payload, background_connections, connection_records,
                    )
                    if background_connections else []
                ),
                split_mode,
            ),
        },
    }
    # Preserve the original flattened page keys for older UI readers.
    return {
        **page_quality,
        "page_attributed": page_quality,
        "capture_global": capture_global,
    }


ANALYSIS_INTEGRITY_CODES = frozenset({
    "POST_FLOW_UNAVAILABLE",
    "REQUEST_ATTRIBUTION_UNMATCHED",
    "REQUEST_ATTRIBUTION_AMBIGUOUS",
    "TRANSPORT_UNMATCHED",
    "TRANSPORT_AMBIGUOUS",
    "EGRESS_UNAVAILABLE",
    "PCAP_PRE_EMPTY",
    "PCAP_POST_UNAVAILABLE",
})


def _analysis_integrity_state(
    consistency: dict, warnings: list[dict], *, scope: str,
) -> str:
    if consistency.get("status") != "passed":
        return "failed"
    if any(w.get("scope") == scope and w.get("code") == "PACKET_CAPTURE_INCOMPLETE" for w in warnings):
        return "failed"
    return (
        "degraded"
        if any(
            warning.get("scope") == scope
            and warning.get("code") in ANALYSIS_INTEGRITY_CODES
            and warning.get("severity") != "info"
            for warning in warnings
        )
        else "passed"
    )


def _network_scope_summary(
    records: list[dict], *, local_ids: set[str], id_field: str,
) -> dict:
    counts = Counter(
        post_flow_disposition(
            record, local_endpoint=record.get(id_field) in local_ids,
        )
        for record in records
    )
    applicable = (
        counts["with_post_flow"] + counts["failed_before_socket"]
        + counts["unexpected_missing"]
    )
    failures = counts["failed_before_socket"]
    if counts["unexpected_missing"]:
        state = "indeterminate"
    elif applicable == 0:
        state = "not_applicable"
    elif failures == 0:
        state = "healthy"
    elif counts["with_post_flow"] == 0:
        state = "failed"
    else:
        state = "partial_failure"
    return {
        "state": state, "applicable": applicable,
        "established": counts["with_post_flow"],
        "failed_before_socket": failures,
        "explicit_no_socket": counts["explicit_no_socket"],
        "local_not_applicable": counts["local_not_applicable"],
        "unexpected_missing": counts["unexpected_missing"],
    }


def _browser_request_failure_summary(records: list[dict]) -> dict:
    """Summarize observed CDP failures without treating retries as correlation loss."""

    latest_successful_index: dict[str, int] = {}
    for index, record in enumerate(records):
        failure = record.get("failure", {})
        url = urldefrag(str(record.get("url", "")))[0]
        if url and not failure.get("failed", False):
            latest_successful_index[url] = index

    failed_occurrences = 0
    by_reason: Counter[str] = Counter()
    by_relation: Counter[str] = Counter()
    recovered_by_reason: Counter[str] = Counter()
    canceled = 0
    recovered = 0
    for index, record in enumerate(records):
        failure = record.get("failure", {})
        if not failure.get("failed", False):
            continue
        failed_occurrences += 1
        reason = str(failure.get("reason") or "loading_failed")
        relation = str(record.get("relation") or "unknown")
        by_reason[reason] += 1
        by_relation[relation] += 1
        canceled += int(bool(failure.get("canceled", False)))
        url = urldefrag(str(record.get("url", "")))[0]
        was_recovered = bool(
            url and latest_successful_index.get(url, -1) > index
        )
        if was_recovered:
            recovered += 1
            recovered_by_reason[reason] += 1

    return {
        "total_requests": len(records),
        "failed_occurrences": failed_occurrences,
        "canceled_occurrences": canceled,
        "recovered_occurrences": recovered,
        "unrecovered_occurrences": failed_occurrences - recovered,
        "by_reason": dict(sorted(by_reason.items())),
        "by_relation": dict(sorted(by_relation.items())),
        "recovered_by_reason": dict(sorted(recovered_by_reason.items())),
        "recovery_evidence": "later_successful_occurrence_same_url",
    }


def _network_outcome_summary(
    requests: list[dict], connections: list[dict], core_records: list[dict],
    local_core_ids: set[str],
) -> dict:
    local_connections = _local_connection_ids(requests, connections)
    page_connections, _background_connections = _scoped_connection_records(
        connections,
    )
    page = _network_scope_summary(
        page_connections, local_ids=local_connections, id_field="connection_id",
    )
    page["failed_requests"] = sum(
        bool(record.get("failure", {}).get("failed")) for record in requests
    )
    global_scope = _network_scope_summary(
        core_records, local_ids=local_core_ids, id_field="conn_id",
    )
    return {"page_attributed": page, "capture_global": global_scope}


def _quality_warnings(
    request_records: list[dict],
    connection_records: list[dict],
    pcap_payload: dict,
    target_url: str = "",
) -> list[dict]:
    warnings: list[dict] = []
    page_connections, background_connections = _scoped_connection_records(
        connection_records,
    )
    local_connection_ids = _local_connection_ids(request_records, connection_records)
    applicable_connections = [
        record for record in page_connections
        if record.get("connection_id") not in local_connection_ids
    ]
    socket_applicable_connections = [
        record for record in applicable_connections
        if not _egress_without_socket(record)
    ]
    request_partition = _request_partition(request_records)
    if request_partition["unmatched"]:
        warnings.append(_warning(
            "REQUEST_ATTRIBUTION_UNMATCHED",
            request_partition["unmatched"],
            "Some network requests could not be attributed to a browser transport.",
            scope="page_attributed",
        ))
    if request_partition["ambiguous"]:
        warnings.append(_warning(
            "REQUEST_ATTRIBUTION_AMBIGUOUS",
            request_partition["ambiguous"],
            "Some network requests have multiple possible browser transports.",
            scope="page_attributed",
        ))
    transport = _partition(
        record.get("match", {}).get("status", "unmatched")
        for record in page_connections
    )
    if transport["unmatched"]:
        warnings.append(_warning(
            "TRANSPORT_UNMATCHED",
            transport["unmatched"],
            "Some browser transports could not be matched to Mihomo flows.",
            scope="page_attributed",
        ))
    if transport["ambiguous"]:
        warnings.append(_warning(
            "TRANSPORT_AMBIGUOUS",
            transport["ambiguous"],
            "Some browser transports match multiple Mihomo flows.",
            scope="page_attributed",
        ))
    network_failures = sum(
        record.get("post_flow") is None and terminal_is_failure(record)
        for record in socket_applicable_connections
    )
    if network_failures:
        warnings.append(_warning(
            "EGRESS_FAILED_BEFORE_SOCKET",
            network_failures,
            "Observed page network failures ended before an egress socket was established.",
            scope="page_attributed", severity="info",
        ))
    unavailable = sum(
        record.get("post_flow") is None
        and not terminal_is_failure(record)
        for record in socket_applicable_connections
    )
    if unavailable:
        warnings.append(_warning(
            "EGRESS_UNAVAILABLE",
            unavailable,
            "Some page-attributed flows have no complete egress tuple.",
            scope="page_attributed",
        ))
    target_non_network = _target_document_non_network(request_records, target_url)
    if target_non_network:
        warnings.append(_warning(
            "TARGET_DOCUMENT_NON_NETWORK",
            target_non_network,
            "The primary target document was served entirely without network transport.",
            scope="page_attributed",
        ))
    if pcap_payload.get("split_mode") == "unique_connections":
        pcap_connections = _scoped_pcap_connections(
            pcap_payload, page_connections, connection_records,
        )
        pre_missing = sum(
            item.get("pre_proxy", {}).get("status") != "success"
            for item in pcap_connections
        )
        post_missing = sum(
            item.get("post_proxy", {}).get("status")
            not in {"success", "not_applicable", "not_requested"}
            for item in pcap_connections
        )
        post_not_applicable = sum(
            item.get("post_proxy", {}).get("status") == "not_applicable"
            for item in pcap_connections
        )
        post_not_requested = sum(
            item.get("post_proxy", {}).get("status") == "not_requested"
            for item in pcap_connections
        )
        if pre_missing:
            warnings.append(_warning(
                "PCAP_PRE_EMPTY",
                pre_missing,
                "Some pre-proxy PCAP extracts are empty or failed.",
                scope="page_attributed",
            ))
        if post_missing:
            warnings.append(_warning(
                "PCAP_POST_UNAVAILABLE",
                post_missing,
                "Some applicable post-proxy PCAP extracts are empty or unavailable.",
                scope="page_attributed",
            ))
        if post_not_applicable:
            warnings.append(_warning(
                "PCAP_POST_NOT_APPLICABLE",
                post_not_applicable,
                "Post-proxy PCAP is not applicable to explicit no-socket or local outcomes.",
                scope="page_attributed", severity="info",
            ))
        if post_not_requested:
            warnings.append(_warning(
                "PCAP_POST_NOT_REQUESTED",
                post_not_requested,
                "Post-proxy PCAP was not requested because no outbound tuple was available for extraction.",
                scope="page_attributed", severity="info",
            ))
    if local_connection_ids:
        warnings.append(_warning(
            "LOCAL_ENDPOINT_UNAVAILABLE",
            len(local_connection_ids),
            "Local client probes were observed; post-proxy flow is not applicable.",
            scope="page_attributed",
            severity="info",
        ))
    background_transport = _partition(
        record.get("match", {}).get("status", "unmatched")
        for record in background_connections
    )
    for status, code in (
        ("unmatched", "BROWSER_BACKGROUND_TRANSPORT_UNMATCHED"),
        ("ambiguous", "BROWSER_BACKGROUND_TRANSPORT_AMBIGUOUS"),
    ):
        if background_transport[status]:
            warnings.append(_warning(
                code,
                background_transport[status],
                "Browser-background transport attempts are retained as capture diagnostics.",
                scope="capture_global", severity="info",
            ))
    if (
        background_connections
        and pcap_payload.get("split_mode") == "unique_connections"
    ):
        background_pcaps = _scoped_pcap_connections(
            pcap_payload, background_connections, connection_records,
        )
        background_pre_missing = sum(
            item.get("pre_proxy", {}).get("status") != "success"
            for item in background_pcaps
        )
        if background_pre_missing:
            warnings.append(_warning(
                "BROWSER_BACKGROUND_PCAP_PRE_EMPTY",
                background_pre_missing,
                "Browser-background attempts have empty or failed pre-proxy extracts.",
                scope="capture_global", severity="info",
            ))
    return warnings


def _scoped_connection_records(
    connection_records: list[dict],
) -> tuple[list[dict], list[dict]]:
    """Split page and background transports, retaining legacy behavior."""
    if not any("attribution_scope" in record for record in connection_records):
        return list(connection_records), []
    return (
        [
            record for record in connection_records
            if record.get("attribution_scope") == "page_attributed"
        ],
        [
            record for record in connection_records
            if record.get("attribution_scope") == "browser_background"
        ],
    )


def _scoped_pcap_connections(
    pcap_payload: dict,
    selected_connections: list[dict],
    all_connections: list[dict],
) -> list[dict]:
    pcaps = list(pcap_payload.get("connections", []))
    if not any("attribution_scope" in record for record in all_connections):
        return pcaps
    selected_ids = {
        record.get("connection_id") for record in selected_connections
        if record.get("connection_id")
    }
    return [item for item in pcaps if item.get("connection_id") in selected_ids]


def _pcap_quality(pcap_connections: list[dict], split_mode: str) -> dict:
    applicable = [
        item for item in pcap_connections
        if item.get("post_proxy", {}).get("status")
        not in {"not_applicable", "not_requested"}
    ]
    return {
        "requested": split_mode == "unique_connections",
        "total": len(pcap_connections),
        "pre_success": sum(
            item.get("pre_proxy", {}).get("status") == "success"
            for item in pcap_connections
        ),
        "post_applicable": len(applicable),
        "post_success": sum(
            item.get("post_proxy", {}).get("status") == "success"
            for item in applicable
        ),
        "complete_pairs": sum(
            item.get("pre_proxy", {}).get("status") == "success"
            and item.get("post_proxy", {}).get("status") == "success"
            for item in applicable
        ),
    }


def _local_connection_ids(
    request_records: list[dict],
    connection_records: list[dict] | None = None,
) -> set[str]:
    observations: dict[str, set[str]] = {}
    for record in request_records:
        connection_id = record.get("connection_id")
        if not connection_id:
            continue
        observations.setdefault(connection_id, set()).add(
            record.get("network_observation", "unknown")
        )
    local_ids = {
        connection_id
        for connection_id, values in observations.items()
        if values and values <= {"local_endpoint"}
    }
    local_ids.update(
        record.get("connection_id")
        for record in (connection_records or [])
        if record.get("connection_id") and _record_targets_loopback(record)
    )
    return local_ids


def _record_targets_loopback(record: dict) -> bool:
    for name in ("pre_flow", "post_flow"):
        flow = record.get(name)
        if not isinstance(flow, dict):
            continue
        for field in ("src_ip", "dst_ip"):
            try:
                if ip_address(flow.get(field, "")).is_loopback:
                    return True
            except ValueError:
                pass
    terminal = record.get("terminal")
    error = terminal.get("error", "") if isinstance(terminal, dict) else ""
    return _text_targets_loopback(error)


def _mapping_targets_loopback(mapping: FlowMapping) -> bool:
    for flow in (mapping.pre_flow, mapping.post_flow):
        if flow is None:
            continue
        for value in (flow.src_ip, flow.dst_ip):
            try:
                if ip_address(value).is_loopback:
                    return True
            except ValueError:
                pass
    return _text_targets_loopback(mapping.error)


def _text_targets_loopback(error: str) -> bool:
    if "::1" in error:
        return True
    for value in re.findall(
        r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", error,
    ):
        try:
            if ip_address(value).is_loopback:
                return True
        except ValueError:
            pass
    return False


def _mapping_error_class(mapping: FlowMapping) -> str:
    return terminal_error_class(
        status=mapping.status, stage=mapping.stage, error=mapping.error,
        explicit=mapping.error_class,
    )[0] or "transport_failure"


def _local_core_ids(
    connection_records: list[dict],
    core_records: list[dict],
    local_connection_ids: set[str],
) -> set[str]:
    local_pre_endpoints = {
        (
            record.get("pre_flow", {}).get("network"),
            record.get("pre_flow", {}).get("dst_ip"),
            record.get("pre_flow", {}).get("dst_port"),
        )
        for record in connection_records
        if record.get("connection_id") in local_connection_ids
    }
    return {
        record.get("conn_id")
        for record in core_records
        if (
            record.get("pre_flow", {}).get("network"),
            record.get("pre_flow", {}).get("dst_ip"),
            record.get("pre_flow", {}).get("dst_port"),
        ) in local_pre_endpoints
        and record.get("conn_id")
    }


def _target_url(session: Path) -> str:
    context = _read_index(session / "raw" / "capture-context.json")
    target = context.get("target")
    return target.get("url", "") if isinstance(target, dict) else ""


def _playback_summary(session: Path) -> dict | None:
    context = _read_index(session / "raw" / "capture-context.json")
    playback = context.get("playback")
    if not isinstance(playback, dict):
        return None
    return playback


def _playback_scenario_outcome(playback: dict) -> dict:
    goal_met = playback.get("primary_goal_met") is True
    primary_seconds = playback.get("primary_content_seconds", 0)
    observed_value = playback.get("primary_content_observed")
    primary_observed = (
        observed_value
        if isinstance(observed_value, bool)
        else (
            goal_met
            or (
                isinstance(primary_seconds, (int, float))
                and primary_seconds > 0
            )
        )
    )
    quality = playback.get("quality")
    if goal_met:
        state = "passed"
    elif primary_observed:
        state = "degraded"
    elif quality == "unavailable":
        state = "failed"
    else:
        state = "indeterminate"
    return {
        "kind": "youtube_playback",
        "state": state,
        "reason": playback.get("reason"),
        "primary_content_observed": primary_observed,
        "primary_goal_met": goal_met,
        "primary_content_seconds": primary_seconds,
        "desired_primary_seconds": playback.get("desired_primary_seconds", 0),
        "ad_observed": playback.get("ad_observed"),
        "skippable_ad_observed": playback.get("skippable_ad_observed"),
        "skip_confirmed": playback.get("skip_confirmed"),
    }


def _target_document_non_network(records: list[dict], target_url: str) -> int:
    if not target_url:
        return 0
    target, _ = urldefrag(target_url)
    exact = [
        record for record in records
        if str(record.get("resource_type", "")).lower() == "document"
        and urldefrag(str(record.get("url", "")))[0] == target
    ]
    return (
        len(exact)
        if exact and all(
            record.get("network_observation") in NON_NETWORK_OBSERVATIONS
            for record in exact
        )
        else 0
    )


def _outcome_without_socket(outcome: object) -> bool:
    return outcome_without_socket(outcome)


def _egress_without_socket(record: dict) -> bool:
    return record_without_socket(record)


def _warning(
    code: str,
    count: int,
    message: str,
    *,
    scope: str,
    severity: str = "warning",
) -> dict:
    return {
        "code": code,
        "count": count,
        "message": message,
        "scope": scope,
        "severity": severity,
        "affects_page_quality": (
            scope == "page_attributed" and severity != "info"
        ),
    }


def _quality_state(
    consistency: dict,
    warnings: list[dict],
    *,
    scope: str,
) -> str:
    if consistency.get("status") != "passed":
        return "failed"
    if any(w.get("scope") == scope and w.get("code") == "PACKET_CAPTURE_INCOMPLETE" for w in warnings):
        return "failed"
    degradation_codes = {
        "POST_FLOW_UNAVAILABLE",
        "FLOW_ERRORS",
        "REQUEST_ATTRIBUTION_UNMATCHED",
        "REQUEST_ATTRIBUTION_AMBIGUOUS",
        "TRANSPORT_UNMATCHED",
        "TRANSPORT_AMBIGUOUS",
        "EGRESS_DIAL_FAILED",
        "EGRESS_UNAVAILABLE",
        "PCAP_PRE_EMPTY",
        "PCAP_POST_UNAVAILABLE",
        "TARGET_DOCUMENT_NON_NETWORK",
    }
    return (
        "degraded"
        if any(
            item.get("scope") == scope
            and item.get("severity") != "info"
            and item.get("code") in degradation_codes
            for item in warnings
        )
        else "passed"
    )
