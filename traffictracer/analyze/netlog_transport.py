"""NetLog transport tracer — match CDP-attributed requests to NetLog sockets."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from ..models import AttributedRequest, TransportConnection
from ..utils import logger

from parser.constants import (
    NetLogConstants, SRC_URL_REQUEST, SRC_TRANSPORT_CONNECT_JOB, SRC_SOCKET,
    SRC_SSL_CONNECT_JOB, SRC_SOCKS_CONNECT_JOB, SRC_HTTP_PROXY_CONNECT_JOB,
    SRC_WEB_SOCKET_TRANSPORT_CONNECT_JOB, SRC_HTTP2_SESSION, SRC_QUIC_SESSION,
    SRC_PROXY_CLIENT_SOCKET, SRC_TCP_STREAM_ATTEMPT, SRC_TLS_STREAM_ATTEMPT,
)
from parser.event_processor import process_events
from parser.dependency_graph import (
    build_connection_chain,
    _build_children_index,
    _parse_ip_port,
)


def trace_transport(
    requests: list[AttributedRequest],
    netlog_path: str,
) -> list[TransportConnection]:
    fp = Path(netlog_path)
    if not fp.exists():
        raise FileNotFoundError(f"NetLog file not found: {netlog_path}")

    with open(fp, "r", encoding="utf-8") as f:
        raw = json.load(f)

    constants = NetLogConstants(raw.get("constants") or {})
    events = raw.get("events") or []
    entries = process_events(events, constants)
    children_index = _build_children_index(entries)

    request_urls: dict[str, list[str]] = {}
    for req in requests:
        normalized = _normalize_url(req.url)
        request_urls.setdefault(normalized, []).append(req.request_id)

    netlog_url_index: dict[str, list[int]] = {}
    for sid, entry in entries.items():
        if entry.source_type != SRC_URL_REQUEST:
            continue
        url = _extract_url_from_entry(entry)
        if url:
            normalized = _normalize_url(url)
            netlog_url_index.setdefault(normalized, []).append(sid)

    connections_by_source: dict[int, TransportConnection] = {}
    seen_source_ids: set[int] = set()

    for normalized_url, source_ids in netlog_url_index.items():
        if normalized_url not in request_urls:
            continue

        matched_request_ids = request_urls[normalized_url]

        for sid in source_ids:
            if sid in seen_source_ids:
                continue
            seen_source_ids.add(sid)

            chain = build_connection_chain(sid, entries, children_index)
            ft = chain.five_tuple

            sibling_source_id = None
            if not _complete_five_tuple(ft):
                sibling_source_id = _fill_from_siblings(sid, entries, children_index, ft)

            # A connection record represents a real pre-proxy flow. Requests
            # without a complete transport remain explicit unmatched request
            # records instead of becoming invalid partial connection records.
            if not _complete_five_tuple(ft):
                continue

            transport_source_id = _transport_source_id(chain, sibling_source_id or sid)
            first_observed = min(
                (req.timestamp for req in requests if req.request_id in matched_request_ids),
                default=None,
            )
            existing = connections_by_source.get(transport_source_id)
            if existing is not None:
                existing.request_ids = list(dict.fromkeys([*existing.request_ids, *matched_request_ids]))
                if first_observed is not None:
                    existing.first_observed = (
                        min(existing.first_observed, first_observed)
                        if existing.first_observed is not None
                        else first_observed
                    )
                continue

            connections_by_source[transport_source_id] = TransportConnection(
                netlog_source_id=transport_source_id,
                url=_denormalize_url(normalized_url),
                src_ip=ft.src_ip or "",
                src_port=ft.src_port or 0,
                dst_ip=ft.dst_ip or "",
                dst_port=ft.dst_port or 0,
                protocol=ft.protocol or "",
                request_ids=list(matched_request_ids),
                first_observed=first_observed,
            )

    connections = _merge_alias_connections(list(connections_by_source.values()))
    logger.info("Traced %d transport connections for %d CDP requests",
                len(connections), len(requests))
    return connections


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
    for child_id in children_index.get(parent_id, []):
        if child_id == sid:
            continue
        child = entries.get(child_id)
        if child is None or child.source_type not in _SIBLING_TRANSPORT_TYPES:
            continue
        for event in child.entries:
            params = event.get("params") or {}
            local = params.get("local_address")
            remote = params.get("remote_address")
            if not (isinstance(local, str) and isinstance(remote, str)):
                continue
            if not ft.src_ip:
                parsed = _parse_ip_port(local)
                if parsed:
                    ft.src_ip, ft.src_port = parsed
            if not ft.dst_ip:
                parsed = _parse_ip_port(remote)
                if parsed:
                    ft.dst_ip, ft.dst_port = parsed
            if _complete_five_tuple(ft):
                return int(child_id)
    return None


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
}


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
    return merged


def _transport_tuple(connection: TransportConnection) -> tuple:
    return (
        connection.protocol.lower(),
        connection.src_ip, connection.src_port,
        connection.dst_ip, connection.dst_port,
    )


def _complete_five_tuple(ft) -> bool:
    return bool(ft.src_ip and ft.src_port and ft.dst_ip and ft.dst_port)
