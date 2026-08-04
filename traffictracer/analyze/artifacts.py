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

    error_count = sum(bool(mapping.error) for mapping in mappings)
    warnings = _warnings(items, pre_counts, error_count)
    match_counts = Counter(item["match"]["status"] for item in items)
    protocol_counts = Counter(item["protocol"] for item in items)
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
    }
    results = Path(output_dir) if output_dir is not None else session / "results"
    request_records, connection_records, generation_id = _v2_records(results)
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
    browser = _partition(
        record.get("attribution", {}).get("status", "unmatched")
        for record in request_records
    )
    transport = _partition(
        record.get("match", {}).get("status", "unmatched")
        for record in connection_records
    )
    reasons: Counter[str] = Counter()
    for record in request_records:
        attribution = record.get("attribution", {})
        if attribution.get("status") != "matched":
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

    core_records = (
        core_flow_records
        if core_flow_records is not None
        else connection_records
    )
    with_post = shared = 0
    for record in core_records:
        if record.get("post_flow") is not None:
            with_post += 1
        else:
            reasons["missing_post_flow"] += 1
        if bool(record.get("shared")):
            shared += 1
    total = len(core_records)
    coverage = {
        "browser_requests": browser,
        "transport_connections": transport,
        "core_logical_flows": {
            "total": total,
            "with_post_flow": with_post,
            "shared": shared,
            "missing_post_flow": total - with_post,
        },
        "unmatched_reasons": dict(sorted(reasons.items())),
    }
    _assert_coverage_conservation(coverage)
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


def _assert_coverage_conservation(coverage: dict) -> None:
    for name in ("browser_requests", "transport_connections"):
        partition = coverage[name]
        accounted = sum(
            partition[key] for key in ("matched", "ambiguous", "unmatched")
        )
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
    for trace_path in sorted((session / "logs").glob("mihomo_trace_*.jsonl")):
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
    warnings: list[dict] = []
    duplicate_keys = sorted(key for key, count in pre_counts.items() if count > 1)
    if duplicate_keys:
        warnings.append({
            "code": "DUPLICATE_PRE_FLOW",
            "count": len(duplicate_keys),
            "message": "Some pre-proxy tuples map to multiple logical flows.",
            "keys": duplicate_keys,
        })
    shared_count = sum(bool(item["shared"]) for item in items)
    if shared_count:
        warnings.append({
            "code": "SHARED_OUTER_FLOW",
            "count": shared_count,
            "message": "Shared outer flows are not exclusive one-to-one mappings.",
        })
    missing_count = sum(item["post_flow"] is None for item in items)
    if missing_count:
        warnings.append({
            "code": "POST_FLOW_UNAVAILABLE",
            "count": missing_count,
            "message": "Some logical flows have no complete post-proxy tuple.",
        })
    if error_count:
        warnings.append({
            "code": "FLOW_ERRORS",
            "count": error_count,
            "message": "Some logical flows ended with a tracing error.",
        })
    return warnings
