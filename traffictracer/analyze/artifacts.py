"""Persist UI-ready normalized Flow index and analysis summary artifacts."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import json
from pathlib import Path

from traffictracer.contracts import validate_flow
from traffictracer.models import FlowTuple
from traffictracer.session.atomic import write_json_atomic
from traffictracer.version import FLOW_SCHEMA_VERSION

from .flow_index import FlowIndex, FlowMapping
from .consistency import validate_analysis_consistency


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

    error_count = sum(bool(mapping.error) for mapping in mappings)
    warnings = _warnings(items, pre_counts, error_count)
    warnings.extend(_quality_warnings(request_records, connection_records, pcap_payload))
    match_counts = Counter(item["match"]["status"] for item in items)
    protocol_counts = Counter(item["protocol"] for item in items)
    quality = analysis_quality(
        request_records, connection_records, pcap_payload, items, error_count,
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
    }
    summary_payload["coverage"] = layered_coverage(
        request_records,
        connection_records,
        items,
    )
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
) -> dict:
    """Recompute conservative layer-specific coverage from persisted indexes."""
    browser = _request_partition(request_records)
    transport = _partition(
        record.get("match", {}).get("status", "unmatched")
        for record in connection_records
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
    for record in connection_records:
        match = record.get("match", {})
        if match.get("status") != "matched":
            reasons[_normalized_reason(
                match.get("unmatched_reason"),
                "connection_unmatched",
            )] += 1

    page_reasons = reasons.copy()
    page_logical_records = [
        record for record in connection_records
        if record.get("post_flow") is not None
        or bool(record.get("mihomo_connection_id"))
        or record.get("terminal") is not None
    ]
    page_core = _core_coverage(page_logical_records, page_reasons)
    core_records = (
        core_flow_records
        if core_flow_records is not None
        else connection_records
    )
    global_reasons: Counter[str] = Counter()
    global_core = _core_coverage(core_records, global_reasons)
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
            "unmatched_reasons": dict(sorted(global_reasons.items())),
        },
        "unmatched_reasons": dict(sorted(reasons.items())),
    }
    _assert_coverage_conservation(coverage)
    return coverage


def _core_coverage(records: list[dict], reasons: Counter[str]) -> dict:
    with_post = sum(record.get("post_flow") is not None for record in records)
    missing = len(records) - with_post
    if missing:
        reasons["missing_post_flow"] += missing
    return {
        "total": len(records),
        "with_post_flow": with_post,
        "shared": sum(bool(record.get("shared")) for record in records),
        "missing_post_flow": missing,
    }


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
    non_network = {
        "disk_cache", "service_worker", "prefetch_cache", "browser_internal",
    }
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
    if core["with_post_flow"] + core["missing_post_flow"] != core["total"]:
        raise ValueError("core logical flow coverage does not conserve its total")
    if core["shared"] > core["total"]:
        raise ValueError("shared core logical flow count exceeds total")


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


def _read_index(path: Path) -> dict:
    if not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"analysis index must be an object: {path}")
    return payload


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


def _load_mappings(session: Path) -> list[FlowMapping]:
    mappings: list[FlowMapping] = []
    raw_trace = session / "raw" / "mihomo-trace.jsonl"
    trace_paths = (
        [raw_trace]
        if raw_trace.is_file()
        else sorted((session / "logs").glob("mihomo_trace_*.jsonl"))
    )
    for trace_path in trace_paths:
        mappings.extend(FlowIndex.from_log(str(trace_path)).mappings)
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
    if usable_post is None:
        match_status = "unmatched"
        confidence = 0.0
        reason = "no complete post-proxy flow"
    elif candidate_count > 1:
        match_status = "ambiguous"
        confidence = 0.5
        reason = "pre-proxy tuple is reused by multiple logical flows"
    else:
        match_status = "matched"
        confidence = 1.0
        reason = "exact normalized pre-proxy tuple"

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
    }
    if mapping.outer_conn_id:
        item["outer_conn_id"] = mapping.outer_conn_id
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


def _network(value: str) -> str:
    lowered = value.lower()
    if lowered.startswith("tcp"):
        return "tcp"
    if lowered.startswith("udp"):
        return "udp"
    raise ValueError(f"unsupported normalized flow network: {value}")


def _warnings(
    items: list[dict],
    pre_counts: Counter[str],
    error_count: int,
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
    missing_count = sum(item["post_flow"] is None for item in items)
    if missing_count:
        warnings.append(_warning(
            "POST_FLOW_UNAVAILABLE",
            missing_count,
            "Some capture-global logical flows have no complete post-proxy tuple.",
            scope="capture_global",
        ))
    if error_count:
        warnings.append(_warning(
            "FLOW_ERRORS",
            error_count,
            "Some capture-global logical flows ended with a tracing error.",
            scope="capture_global",
        ))
    return warnings


def analysis_quality(
    request_records: list[dict],
    connection_records: list[dict],
    pcap_payload: dict,
    core_flow_records: list[dict] | None = None,
    core_error_count: int = 0,
) -> dict:
    """Return conservative, denominator-preserving scoped quality metrics."""
    browser = _request_partition(request_records)
    eligible_requests = browser["total"] - browser["non_network"]
    transport = _partition(
        record.get("match", {}).get("status", "unmatched")
        for record in connection_records
    )

    established = sum(
        record.get("post_flow") is not None for record in connection_records
    )
    failed_before_socket = sum(
        record.get("post_flow") is None
        and _is_dial_failure(record.get("terminal"))
        for record in connection_records
    )
    unavailable = len(connection_records) - established - failed_before_socket

    split_mode = pcap_payload.get("split_mode", "none")
    pcap_connections = list(pcap_payload.get("connections", []))
    pre_success = sum(
        item.get("pre_proxy", {}).get("status") == "success"
        for item in pcap_connections
    )
    post_success = sum(
        item.get("post_proxy", {}).get("status") == "success"
        for item in pcap_connections
    )
    complete_pairs = sum(
        item.get("pre_proxy", {}).get("status") == "success"
        and item.get("post_proxy", {}).get("status") == "success"
        for item in pcap_connections
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
            "total": len(connection_records),
            "established": established,
            "failed_before_socket": failed_before_socket,
            "unavailable": unavailable,
        },
        "pcap_extraction": {
            "requested": split_mode == "unique_connections",
            "total": len(pcap_connections),
            "pre_success": pre_success,
            "post_success": post_success,
            "complete_pairs": complete_pairs,
        },
    }
    core_records = core_flow_records or []
    capture_global = {
        "logical_flows": {
            "total": len(core_records),
            "with_post_flow": sum(
                item.get("post_flow") is not None for item in core_records
            ),
            "missing_post_flow": sum(
                item.get("post_flow") is None for item in core_records
            ),
            "errors": core_error_count,
        },
    }
    # Preserve the original flattened page keys for older UI readers.
    return {
        **page_quality,
        "page_attributed": page_quality,
        "capture_global": capture_global,
    }


def _quality_warnings(
    request_records: list[dict],
    connection_records: list[dict],
    pcap_payload: dict,
) -> list[dict]:
    warnings: list[dict] = []
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
        for record in connection_records
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
    dial_failures = sum(
        record.get("post_flow") is None
        and _is_dial_failure(record.get("terminal"))
        for record in connection_records
    )
    if dial_failures:
        warnings.append(_warning(
            "EGRESS_DIAL_FAILED",
            dial_failures,
            "Some page-attributed flows failed before an egress socket was established.",
            scope="page_attributed",
        ))
    unavailable = sum(
        record.get("post_flow") is None
        and not _is_dial_failure(record.get("terminal"))
        for record in connection_records
    )
    if unavailable:
        warnings.append(_warning(
            "EGRESS_UNAVAILABLE",
            unavailable,
            "Some page-attributed flows have no complete egress tuple.",
            scope="page_attributed",
        ))
    if pcap_payload.get("split_mode") == "unique_connections":
        pcap_connections = pcap_payload.get("connections", [])
        pre_missing = sum(
            item.get("pre_proxy", {}).get("status") != "success"
            for item in pcap_connections
        )
        post_missing = sum(
            item.get("post_proxy", {}).get("status") != "success"
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
                "Some post-proxy PCAP extracts are empty or unavailable.",
                scope="page_attributed",
            ))
    return warnings


def _is_dial_failure(terminal: object) -> bool:
    if not isinstance(terminal, dict):
        return False
    return terminal.get("stage") == "dial" or terminal.get("status") == "dial_error"


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
