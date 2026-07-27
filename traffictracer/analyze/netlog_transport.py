"""NetLog transport tracer — match CDP-attributed requests to NetLog sockets."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from ..models import AttributedRequest, TransportConnection
from ..utils import logger

from parser.constants import NetLogConstants, SRC_URL_REQUEST
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

    connections: list[TransportConnection] = []
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

            if not ft.src_ip and not ft.dst_ip:
                _fill_from_siblings(sid, entries, children_index, ft)

            if not ft.src_ip and not ft.dst_ip:
                continue

            connections.append(TransportConnection(
                netlog_source_id=sid,
                url=_denormalize_url(normalized_url),
                src_ip=ft.src_ip or "",
                src_port=ft.src_port or 0,
                dst_ip=ft.dst_ip or "",
                dst_port=ft.dst_port or 0,
                protocol=ft.protocol or "",
                request_ids=list(matched_request_ids),
            ))

    logger.info("Traced %d transport connections for %d CDP requests",
                len(connections), len(requests))
    return connections


def _fill_from_siblings(sid, entries, children_index, ft) -> None:
    entry = entries.get(sid)
    if entry is None:
        return
    parent_id = _find_parent_id(entry)
    if parent_id is None:
        return
    for child_id in children_index.get(parent_id, []):
        if child_id == sid:
            continue
        child = entries.get(child_id)
        if child is None:
            continue
        for event in child.entries:
            params = event.get("params") or {}
            local = params.get("local_address")
            if isinstance(local, str) and not ft.src_ip:
                parsed = _parse_ip_port(local)
                if parsed:
                    ft.src_ip, ft.src_port = parsed
            remote = params.get("remote_address")
            if isinstance(remote, str) and not ft.dst_ip:
                parsed = _parse_ip_port(remote)
                if parsed:
                    ft.dst_ip, ft.dst_port = parsed


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
