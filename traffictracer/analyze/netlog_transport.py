"""NetLog transport tracer — match CDP-attributed requests to NetLog sockets."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urldefrag, urlparse

from ..models import AttributedRequest, TransportConnection
from ..utils import logger
from .process import analysis_checkpoint
from .health import record_analysis_progress

from parser.constants import (
    NetLogConstants, SRC_URL_REQUEST, SRC_TRANSPORT_CONNECT_JOB, SRC_SOCKET,
    SRC_SSL_CONNECT_JOB, SRC_SOCKS_CONNECT_JOB, SRC_HTTP_PROXY_CONNECT_JOB,
    SRC_WEB_SOCKET_TRANSPORT_CONNECT_JOB, SRC_HTTP2_SESSION, SRC_QUIC_SESSION,
    SRC_PROXY_CLIENT_SOCKET, SRC_TCP_STREAM_ATTEMPT, SRC_TLS_STREAM_ATTEMPT,
    SRC_UDP_SOCKET, SOURCE_TYPE_NAMES, EVT_UDP_CONNECT,
    EVT_UDP_LOCAL_ADDRESS,
)
from parser.event_processor import process_events
from parser.dependency_graph import (
    build_connection_chain,
    _build_children_index,
    _parse_ip_port,
    extract_five_tuple,
    dependency_checkpoints,
)


def trace_transport(
    requests: list[AttributedRequest],
    netlog_path: str,
) -> list[TransportConnection]:
    fp = Path(netlog_path)
    if not fp.exists():
        raise FileNotFoundError(f"NetLog file not found: {netlog_path}")

    analysis_checkpoint()
    record_analysis_progress("netlog.read_json")
    from parser.netlog_reader import open_netlog
    def report_events(operation, processed, total):
        analysis_checkpoint()
        record_analysis_progress("netlog." + operation, processed, total)

    with open_netlog(fp, analysis_checkpoint) as (raw_constants, events):
        constants = NetLogConstants(raw_constants)
        time_tick_offset = _time_tick_offset_seconds(raw_constants)
        entries = process_events(events, constants, progress=report_events)
    analysis_checkpoint()
    record_analysis_progress("netlog.index_dependencies", 0, len(entries))
    children_index = _build_children_index(entries)

    observations: list[dict] = []
    # Only these keys can participate in either binding pass below. Keep the
    # full source graph for dependencies, but avoid tracing unrelated requests.
    requested_urls = {_normalize_url(request.url) for request in requests}
    exact_requested_urls = {_exact_url(request.url) for request in requests}
    for index, (sid, entry) in enumerate(entries.items()):
        if index % 128 == 0:
            analysis_checkpoint()
            record_analysis_progress("netlog.trace_sources", index, len(entries))
        if entry.source_type != SRC_URL_REQUEST:
            continue
        url = _extract_url_from_entry(entry)
        if not url:
            continue
        if _normalize_url(url) not in requested_urls and _exact_url(url) not in exact_requested_urls:
            continue
        with dependency_checkpoints(analysis_checkpoint):
            chain = build_connection_chain(sid, entries, children_index)
        ft = chain.five_tuple
        _prefer_coherent_quic_udp_endpoints(
            chain, entries, children_index, ft,
        )
        sibling_source_id = None
        if not _complete_five_tuple(ft):
            sibling_source_id = _fill_from_siblings(sid, entries, children_index, ft)

        # A connection record represents a real pre-proxy flow. Requests
        # without a complete transport remain explicit unmatched request
        # records instead of becoming invalid partial connection records.
        if not _complete_five_tuple(ft):
            continue
        if not _is_http_transport(url, ft):
            logger.debug(
                "Ignoring resolver endpoint selected as transport for %s: %s:%s",
                url,
                ft.dst_ip,
                ft.dst_port,
            )
            continue
        observations.append({
            "sid": sid,
            "url": url,
            "chain": chain,
            "five_tuple": ft,
            "transport_source_id": _transport_source_id(
                chain, sibling_source_id or sid,
            ),
            "sort_key": _entry_sort_key(entry, sid),
        })

    analysis_checkpoint()
    record_analysis_progress("netlog.bind_requests", 0, len(requests))
    request_bindings = _bind_request_occurrences(requests, observations)
    record_analysis_progress("netlog.bind_requests", len(requests), len(requests))
    requests_by_id = {request.request_id: request for request in requests}
    connections_by_source: dict[int, TransportConnection] = {}
    for observation in observations:
        matched_request_ids = request_bindings.get(observation["sid"], [])
        if not matched_request_ids:
            continue
        matched_requests = [
            requests_by_id[item] for item in matched_request_ids
        ]
        first_observed = min(
            (item.timestamp for item in matched_requests),
            default=None,
        )
        last_observed = max(
            (_request_end(item) for item in matched_requests),
            default=None,
        )
        first_observed_utc = (
            time_tick_offset + first_observed
            if time_tick_offset is not None and first_observed is not None
            else None
        )
        last_observed_utc = (
            time_tick_offset + last_observed
            if time_tick_offset is not None and last_observed is not None
            else None
        )
        transport_source_id = observation["transport_source_id"]
        existing = connections_by_source.get(transport_source_id)
        if existing is not None:
            existing.request_ids = list(dict.fromkeys([
                *existing.request_ids, *matched_request_ids,
            ]))
            if first_observed is not None:
                existing.first_observed = (
                    min(existing.first_observed, first_observed)
                    if existing.first_observed is not None
                    else first_observed
                )
            if last_observed is not None:
                existing.last_observed = (
                    max(existing.last_observed, last_observed)
                    if existing.last_observed is not None
                    else last_observed
                )
            if first_observed_utc is not None:
                existing.first_observed_utc = (
                    min(existing.first_observed_utc, first_observed_utc)
                    if existing.first_observed_utc is not None
                    else first_observed_utc
                )
            if last_observed_utc is not None:
                existing.last_observed_utc = (
                    max(existing.last_observed_utc, last_observed_utc)
                    if existing.last_observed_utc is not None
                    else last_observed_utc
                )
            continue

        ft = observation["five_tuple"]
        connections_by_source[transport_source_id] = TransportConnection(
            netlog_source_id=transport_source_id,
            url=observation["url"],
            src_ip=ft.src_ip or "",
            src_port=ft.src_port or 0,
            dst_ip=ft.dst_ip or "",
            dst_port=ft.dst_port or 0,
            protocol=ft.protocol or "",
            request_ids=list(matched_request_ids),
            first_observed=first_observed,
            last_observed=last_observed,
            first_observed_utc=first_observed_utc,
            last_observed_utc=last_observed_utc,
            network=ft.network or "",
            attempted_protocols=list(ft.attempted_protocols),
            application_protocol=_application_protocol(observation["chain"], ft),
            endpoint_provenance=dict(ft.endpoint_provenance),
        )

    connections = _merge_alias_connections(list(connections_by_source.values()))
    logger.info("Traced %d transport connections for %d CDP requests",
                len(connections), len(requests))
    return connections


def _time_tick_offset_seconds(constants: dict) -> float | None:
    raw = constants.get("timeTickOffset")
    try:
        milliseconds = float(raw)
    except (TypeError, ValueError):
        return None
    return milliseconds / 1000.0 if milliseconds > 0 else None


def _request_end(request: AttributedRequest) -> float:
    return (
        request.completion_timestamp
        or request.response_timestamp
        or request.timestamp
    )


def _transport_source_id(chain, fallback: int) -> int:
    for entry in (
        chain.h2_session,
        chain.quic_session,
        chain.socket,
        chain.tcp_attempt,
        chain.tls_attempt,
        chain.connect_job,
    ):
        if entry is not None:
            return int(entry.source_id)
    return fallback


def _fill_from_siblings(sid, entries, children_index, ft) -> int | None:
    entry = entries.get(sid)
    if entry is None:
        return None
    parent_id = _find_parent_id(entry)
    if parent_id is None:
        return None
    candidates: list[tuple[int, int, object, str]] = []
    expected_network = (ft.network or "").lower()
    for child_id in children_index.get(parent_id, []):
        if child_id == sid:
            continue
        child = entries.get(child_id)
        if child is None or child.source_type not in _SIBLING_TRANSPORT_TYPES:
            continue
        candidate = _endpoint_candidate(child)
        if candidate is None:
            continue
        candidate_network = (candidate.network or "").lower()
        if expected_network and candidate_network != expected_network:
            continue
        candidates.append((
            int(child_id), int(child.source_type), candidate,
            "protocol_compatible_sibling",
        ))
    return _apply_unique_endpoint_candidate(ft, candidates)


def _prefer_coherent_quic_udp_endpoints(
    chain, entries, children_index, ft,
) -> int | None:
    """Recover one QUIC attempt from its own UDP socket only.

    Chromium may retain a failed QUIC session beside a later TCP fallback.
    The generic dependency walk can see both branches. When the selected
    transport is UDP, replace the whole endpoint pair from a uniquely related
    UDP socket instead of combining the TCP local port with the QUIC peer.
    """
    if chain.quic_session is None or (ft.network or "").lower() != "udp":
        return None
    roots = {
        int(chain.quic_session.source_id),
        *(int(item) for item in _parent_ids(chain.quic_session)),
    }
    if chain.pool_group is not None:
        roots.add(int(chain.pool_group.source_id))
    candidates: list[tuple[int, int, object, str]] = []
    for source_id in _descendants_of_types(
        roots, entries, children_index, {SRC_UDP_SOCKET}, max_depth=4,
    ):
        entry = entries[source_id]
        candidate = _udp_endpoint_candidate(entry)
        if candidate is not None:
            candidates.append((
                source_id, int(entry.source_type), candidate,
                "quic_dependency_udp_socket",
            ))
    return _apply_unique_endpoint_candidate(ft, candidates)


def _parent_ids(entry) -> set[int]:
    result: set[int] = set()
    for event in entry.entries:
        params = event.get("params") or {}
        dependency = params.get("source_dependency")
        if isinstance(dependency, dict) and dependency.get("id") is not None:
            result.add(int(dependency["id"]))
    return result


def _descendants_of_types(
    roots, entries, children_index, source_types, *, max_depth: int,
) -> list[int]:
    found: list[int] = []
    seen = set(int(item) for item in roots)
    frontier = [(int(item), 0) for item in roots]
    while frontier:
        parent_id, depth = frontier.pop(0)
        if depth >= max_depth:
            continue
        for child_id in children_index.get(parent_id, []):
            child_id = int(child_id)
            if child_id in seen:
                continue
            seen.add(child_id)
            child = entries.get(child_id)
            if child is None:
                continue
            if child.source_type in source_types:
                found.append(child_id)
            frontier.append((child_id, depth + 1))
    return found


def _endpoint_candidate(entry):
    if entry.source_type == SRC_UDP_SOCKET:
        return _udp_endpoint_candidate(entry)
    candidate = extract_five_tuple([entry])
    if not _complete_five_tuple(candidate):
        return None
    if not candidate.network:
        candidate.network = _source_network(entry.source_type)
    return candidate if candidate.network else None


def _udp_endpoint_candidate(entry):
    candidate = extract_five_tuple([entry])
    local = None
    remote = None
    evidence: list[str] = []
    for event in entry.entries:
        params = event.get("params") or {}
        if event.get("type") == EVT_UDP_CONNECT:
            value = params.get("address")
            if isinstance(value, str) and _parse_ip_port(value):
                remote = _parse_ip_port(value)
                evidence.append("UDP_CONNECT.address")
        elif event.get("type") == EVT_UDP_LOCAL_ADDRESS:
            value = params.get("address")
            if isinstance(value, str) and _parse_ip_port(value):
                local = _parse_ip_port(value)
                evidence.append("UDP_LOCAL_ADDRESS.address")
        for field, side in (
            ("local_address", "local"), ("self_address", "local"),
            ("remote_address", "remote"), ("peer_address", "remote"),
        ):
            value = params.get(field)
            parsed = _parse_ip_port(value) if isinstance(value, str) else None
            if parsed and side == "local":
                local = local or parsed
                evidence.append(field)
            elif parsed:
                remote = remote or parsed
                evidence.append(field)
    if local:
        candidate.src_ip, candidate.src_port = local
    if remote:
        candidate.dst_ip, candidate.dst_port = remote
    candidate.network = "udp"
    candidate.protocol = "QUIC" if candidate.protocol == "QUIC" else "UDP"
    candidate.endpoint_provenance = {
        "event_fields": sorted(set(evidence)),
    }
    return candidate if _complete_five_tuple(candidate) else None


def _source_network(source_type: int) -> str:
    if source_type in _TCP_SIBLING_TYPES:
        return "tcp"
    if source_type in _UDP_SIBLING_TYPES:
        return "udp"
    return ""


def _apply_unique_endpoint_candidate(ft, candidates) -> int | None:
    grouped: dict[tuple, list[tuple[int, int, object, str]]] = {}
    for item in candidates:
        source_id, source_type, candidate, selection = item
        key = (
            (candidate.network or "").lower(),
            candidate.src_ip, candidate.src_port,
            candidate.dst_ip, candidate.dst_port,
        )
        grouped.setdefault(key, []).append(
            (source_id, source_type, candidate, selection)
        )
    if len(grouped) != 1:
        return None
    aliases = next(iter(grouped.values()))
    source_id, source_type, candidate, selection = min(
        aliases, key=lambda item: item[0],
    )
    ft.src_ip, ft.src_port = candidate.src_ip, candidate.src_port
    ft.dst_ip, ft.dst_port = candidate.dst_ip, candidate.dst_port
    ft.network = candidate.network
    if not ft.protocol or ft.protocol in {"HTTP", "HTTPS"}:
        ft.protocol = candidate.protocol
    ft.endpoint_provenance = {
        "source_id": source_id,
        "source_type": SOURCE_TYPE_NAMES.get(source_type, str(source_type)),
        "selection": selection,
        "evidence": candidate.endpoint_provenance.get("event_fields", []),
        "alias_source_ids": sorted(item[0] for item in aliases),
    }
    return source_id


def _find_parent_id(entry) -> int | None:
    for event in entry.entries:
        params = event.get("params") or {}
        sd = params.get("source_dependency")
        if isinstance(sd, dict):
            dep_id = sd.get("id")
            if dep_id is not None:
                return dep_id
    return None


def _extract_url_from_entry(entry) -> str:
    for event in entry.entries:
        params = event.get("params") or {}
        url = params.get("url")
        if isinstance(url, str) and url:
            return url
    if entry.description and entry.description.startswith("http"):
        return entry.description
    return ""


def _bind_request_occurrences(
    requests: list[AttributedRequest],
    observations: list[dict],
) -> dict[int, list[str]]:
    """Bind URL_REQUEST occurrences without broadcasting path aliases."""
    bindings: dict[int, list[str]] = {}
    assigned_requests: set[str] = set()
    assigned_sources: set[int] = set()

    _bind_occurrence_groups(
        requests, observations, _exact_url,
        bindings, assigned_requests, assigned_sources,
    )
    _bind_occurrence_groups(
        requests, observations, _normalize_url,
        bindings, assigned_requests, assigned_sources,
    )
    return bindings


def _bind_occurrence_groups(
    requests: list[AttributedRequest],
    observations: list[dict],
    key_fn,
    bindings: dict[int, list[str]],
    assigned_requests: set[str],
    assigned_sources: set[int],
) -> None:
    request_groups: dict[str, list[AttributedRequest]] = {}
    for request in requests:
        if request.request_id in assigned_requests:
            continue
        request_groups.setdefault(key_fn(request.url), []).append(request)
    source_groups: dict[str, list[dict]] = {}
    for observation in observations:
        if observation["sid"] in assigned_sources:
            continue
        source_groups.setdefault(key_fn(observation["url"]), []).append(observation)

    for key in sorted(set(request_groups).intersection(source_groups)):
        request_group = sorted(
            request_groups[key], key=lambda item: (item.timestamp, item.request_id),
        )
        source_group = sorted(
            source_groups[key], key=lambda item: item["sort_key"],
        )
        if len(source_group) == 1:
            pairs = [(source_group[0], request_group)]
        else:
            pairs = [
                (source, [request])
                for source, request in zip(source_group, request_group)
            ]
        for source, matched in pairs:
            if not matched:
                continue
            source_id = source["sid"]
            bindings[source_id] = [item.request_id for item in matched]
            assigned_sources.add(source_id)
            assigned_requests.update(item.request_id for item in matched)


def _exact_url(url: str) -> str:
    return urldefrag(url).url


def _entry_sort_key(entry, source_id: int) -> tuple[float, int]:
    times: list[float] = []
    for event in entry.entries:
        try:
            times.append(float(event.get("time")))
        except (TypeError, ValueError):
            continue
    return (min(times) if times else float("inf"), source_id)


def _normalize_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def _denormalize_url(normalized: str) -> str:
    return normalized


_SIBLING_TRANSPORT_TYPES = {
    SRC_TRANSPORT_CONNECT_JOB, SRC_SOCKET, SRC_SSL_CONNECT_JOB,
    SRC_SOCKS_CONNECT_JOB, SRC_HTTP_PROXY_CONNECT_JOB,
    SRC_WEB_SOCKET_TRANSPORT_CONNECT_JOB, SRC_HTTP2_SESSION, SRC_QUIC_SESSION,
    SRC_PROXY_CLIENT_SOCKET, SRC_TCP_STREAM_ATTEMPT, SRC_TLS_STREAM_ATTEMPT,
    SRC_UDP_SOCKET,
}

_TCP_SIBLING_TYPES = {
    SRC_TRANSPORT_CONNECT_JOB, SRC_SOCKET, SRC_SSL_CONNECT_JOB,
    SRC_SOCKS_CONNECT_JOB, SRC_HTTP_PROXY_CONNECT_JOB,
    SRC_WEB_SOCKET_TRANSPORT_CONNECT_JOB, SRC_HTTP2_SESSION,
    SRC_PROXY_CLIENT_SOCKET, SRC_TCP_STREAM_ATTEMPT, SRC_TLS_STREAM_ATTEMPT,
}

_UDP_SIBLING_TYPES = {SRC_QUIC_SESSION, SRC_UDP_SOCKET}


def _merge_alias_connections(
    connections: list[TransportConnection],
) -> list[TransportConnection]:
    """Merge NetLog aliases that describe the same active logical flow."""
    merged: list[TransportConnection] = []
    for connection in connections:
        duplicate = next(
            (
                existing for existing in merged
                if _transport_tuple(existing) == _transport_tuple(connection)
                and set(existing.request_ids).intersection(connection.request_ids)
            ),
            None,
        )
        if duplicate is None:
            merged.append(connection)
            continue
        duplicate.request_ids = list(dict.fromkeys([
            *duplicate.request_ids, *connection.request_ids,
        ]))
        if connection.first_observed is not None:
            duplicate.first_observed = (
                min(duplicate.first_observed, connection.first_observed)
                if duplicate.first_observed is not None
                else connection.first_observed
            )
        if connection.last_observed is not None:
            duplicate.last_observed = (
                max(duplicate.last_observed, connection.last_observed)
                if duplicate.last_observed is not None
                else connection.last_observed
            )
    return merged


def _transport_tuple(connection: TransportConnection) -> tuple:
    return (
        (connection.network or connection.protocol).lower(),
        connection.src_ip, connection.src_port,
        connection.dst_ip, connection.dst_port,
    )


def _complete_five_tuple(ft) -> bool:
    return bool(ft.src_ip and ft.src_port and ft.dst_ip and ft.dst_port)


def _is_http_transport(url: str, ft) -> bool:
    """Reject resolver sockets that dependency traversal found below a URL."""
    scheme = urlparse(url).scheme.lower()
    if scheme not in {"http", "https"}:
        return True
    # A URL_REQUEST can retain its DNS branch after the actual HTTP stream is
    # detached or reused. Generic resolver SOCKET entries look complete, but
    # port 53 is DNS evidence rather than the request's business transport.
    return int(ft.dst_port or 0) != 53


def _application_protocol(chain, ft) -> str:
    network = (ft.network or "").lower()
    if network == "udp" and chain.quic_session is not None:
        return "h3"
    if network == "tcp" and chain.h2_session is not None:
        return "h2"
    return "unknown"
