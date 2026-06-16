"""Formatted output — JSON, table, and summary generation."""

from __future__ import annotations

import fnmatch
import json
import sys
from dataclasses import asdict
from typing import Any

from .constants import NetLogConstants
from .source_entry import SourceEntry
from .event_processor import find_events_by_type
from .dependency_graph import (
    ConnectionChain,
    FiveTuple,
    SessionReuse,
    build_connection_chain,
    _build_children_index,
    URL_REQUEST,
    TRANSPORT_CONNECT_JOB,
    SOCKET,
    HTTP2_SESSION,
    QUIC_SESSION,
    HTTP_STREAM_POOL_GROUP,
    HTTP_STREAM_POOL_JOB,
    HTTP_STREAM_POOL_ATTEMPT_MANAGER,
    HTTP_STREAM_POOL_QUIC_TASK,
)
from .dns_resolver import DnsResult


# Column widths for table output
_COL_TYPE = 28
_COL_ID = 6
_COL_DESC = 55


def _pad(s: str, width: int) -> str:
    """Truncate or pad string to exact width."""
    if len(s) > width:
        return s[:width - 2] + ".."
    return s.ljust(width)


def print_connection_chains(
    entries: dict[int, SourceEntry],
    constants: NetLogConstants,
    start_from: str | None = None,
    url_filter: str | None = None,
    file=sys.stdout,
) -> None:
    """Print all connection chains in a readable format.

    If start_from is "url_request", only trace from URL_REQUEST entries.
    If start_from is "socket", only trace from SOCKET entries.
    If url_filter is set, only chains whose URL matches the glob pattern are shown
    (e.g. "*.example.com").
    """
    chains: list[ConnectionChain] = []

    # Determine starting points
    start_types: list[int] = []
    if start_from == "url_request":
        start_types = [URL_REQUEST]
    elif start_from == "socket":
        start_types = [SOCKET]
    else:
        start_types = [URL_REQUEST, SOCKET]

    children_index = _build_children_index(entries)
    seen_ids: set[int] = set()

    for stype in start_types:
        for entry in find_events_by_type(entries, stype):
            sid = entry.source_id
            if sid in seen_ids:
                continue

            chain = build_connection_chain(sid, entries, children_index)
            if chain.is_complete():
                chains.append(chain)
                seen_ids.add(sid)
                # Also mark intermediate entries
                for member in _chain_members(chain):
                    if member:
                        seen_ids.add(member.source_id)

    # Apply URL filter if specified — matches if any chain member's description
    # contains the pattern. This catches SOCKET/CONNECT_JOB descriptions too,
    # not just URL_REQUEST, so chains starting from --start-from socket also
    # benefit from filtering.
    if url_filter:
        def _chain_matches(chain: ConnectionChain, pattern: str) -> bool:
            for member in _chain_members(chain):
                if member and fnmatch.fnmatch(member.description, pattern):
                    return True
            return False

        chains = [c for c in chains if _chain_matches(c, url_filter)]

    # Print chains
    print(f"\n{'=' * 80}", file=file)
    suffix = f" (filtered by '{url_filter}')" if url_filter else ""
    print(f"  Connection Chains  ({len(chains)} total{suffix})", file=file)
    print(f"{'=' * 80}", file=file)

    for i, chain in enumerate(chains, 1):
        print(f"\n-- Chain #{i} --", file=file)

        members: list[tuple[str, SourceEntry | None]] = [
            ("URL_REQUEST", chain.url_request),
            ("HTTP_STREAM_JOB", chain.http_stream_job),
            ("STREAM_JOB_CTRL", chain.http_stream_job_controller),
            ("POOL_GROUP/JOB", chain.pool_group),
            ("CONNECT_JOB", chain.connect_job),
            ("SOCKET", chain.socket),
            ("TCP_ATTEMPT", chain.tcp_attempt),
            ("TLS_ATTEMPT", chain.tls_attempt),
            ("H2_SESSION", chain.h2_session),
            ("QUIC_SESSION", chain.quic_session),
            ("DNS", chain.dns_transaction),
        ]

        for label, obj in members:
            if obj is None:
                continue
            err = " [ERROR]" if obj.is_error else ""
            active = " (active)" if not obj.is_inactive else ""
            print(
                f"  [{_pad(label, 16)} #{obj.source_id:<5}]  "
                f"{obj.description}{err}{active}",
                file=file,
            )

        ft = chain.five_tuple
        ft_str = str(ft) if (ft.dst_ip or ft.dst_port) else "(no IP:port captured)"
        print(f"  {'-' * 60}", file=file)
        print(f"  Five-Tuple: {ft_str}", file=file)

        if chain.url_request:
            print(f"  URL:        {chain.url_request.description}", file=file)


def print_summary(
    entries: dict[int, SourceEntry],
    constants: NetLogConstants,
    file=sys.stdout,
) -> None:
    """Print a summary of the log contents."""
    total = len(entries)
    by_type: dict[str, int] = {}
    total_events = 0
    errors = 0

    for entry in entries.values():
        sname = constants.get_source_name(entry.source_type)
        by_type[sname] = by_type.get(sname, 0) + 1
        total_events += len(entry.entries)
        if entry.is_error:
            errors += 1

    print(f"\n{'=' * 80}", file=file)
    print(f"  NetLog Summary", file=file)
    print(f"{'=' * 80}", file=file)
    print(f"  Total sources:     {total}", file=file)
    print(f"  Total events:      {total_events}", file=file)
    print(f"  Sources with errors: {errors}", file=file)
    print(f"  Client:            {constants.client_info.get('name', '?')} "
          f"v{constants.client_info.get('version', '?')}", file=file)
    print(file=file)
    print(f"  Source types breakdown:", file=file)

    for name in sorted(by_type.keys(), key=lambda n: -by_type[n]):
        count = by_type[name]
        bar = "#" * min(count, 60)
        print(f"    {_pad(name, 36)} {count:>5}  {bar}", file=file)


def print_session_reuse(
    entries: dict[int, SourceEntry],
    constants: NetLogConstants,
    polled_data: dict[str, Any],
    file=sys.stdout,
) -> None:
    """Print HTTP/2 and QUIC session reuse information."""
    reuses: list[SessionReuse] = []

    # From polled data (SPDY/HTTP2 sessions)
    spdy_info = polled_data.get("spdySessionInfo")
    if isinstance(spdy_info, list):
        for s in spdy_info:
            reuses.append(SessionReuse(
                source_id=s.get("source_id", 0),
                session_host=s.get("host_port_pair", ""),
                protocol="HTTP2",
                aliases=s.get("aliases") or [],
                active_streams=s.get("active_streams", 0),
                max_concurrent_streams=s.get("max_concurrent_streams", 0),
            ))

    # From QUIC session info
    quic_info = polled_data.get("quicInfo")
    if isinstance(quic_info, dict):
        quic_sessions = quic_info.get("sessions") or []
        for s in quic_sessions:
            reuses.append(SessionReuse(
                source_id=s.get("source_id", 0),
                session_host=s.get("host", ""),
                protocol="QUIC",
                aliases=s.get("aliases") or [],
                active_streams=s.get("active_streams", 0),
                max_concurrent_streams=s.get("max_concurrent_streams", 0),
            ))

    if not reuses:
        return

    print(f"\n{'=' * 80}", file=file)
    print(f"  Session Reuse (multi-domain connections)", file=file)
    print(f"{'=' * 80}", file=file)

    for r in reuses:
        if not r.aliases:
            continue
        print(file=file)
        print(f"  [{r.protocol}]  #{r.source_id}  {r.session_host}", file=file)
        print(f"    Active Streams: {r.active_streams} / Max: {r.max_concurrent_streams}", file=file)
        print(f"    Aliases: {', '.join(r.aliases)}", file=file)


def print_dns_info(
    dns: DnsResult,
    file=sys.stdout,
) -> None:
    """Print DNS cache entries."""
    print(f"\n{'=' * 80}", file=file)
    print(f"  DNS Resolver Cache", file=file)
    print(f"{'=' * 80}", file=file)
    print(f"  Capacity: {dns.cache_capacity}   "
          f"Active: {dns.active_entries}   "
          f"Expired: {dns.expired_entries}", file=file)

    if dns.dns_config:
        print(f"\n  DNS Config:", file=file)
        for k, v in sorted(dns.dns_config.items()):
            if k in ("can_use_insecure_dns_transactions",
                      "can_use_secure_dns_transactions"):
                continue
            print(f"    {k}: {v}", file=file)

    if not dns.cache_entries:
        print(f"  (no cache entries)", file=file)
        return

    print(f"\n  {'Hostname':<30} {'Addresses':<30} {'TTL':<8} {'Status':<10}", file=file)
    print(f"  {'-' * 30} {'-' * 30} {'-' * 8} {'-' * 10}", file=file)

    for e in dns.cache_entries:
        addrs = ", ".join(e.addresses or e.ip_endpoints or ["(none)"])
        status = "EXPIRED" if e.is_expired else ("ERROR" if e.error else "OK")
        ttl = f"{e.ttl}s" if not e.is_expired else "-"
        print(f"  {_pad(e.hostname, 30)} {_pad(addrs, 30)} {_pad(ttl, 8)} {status}", file=file)

        if e.error:
            print(f"    -> error: {e.error_name} ({e.error})", file=file)


def export_json(
    entries: dict[int, SourceEntry],
    constants: NetLogConstants,
    polled_data: dict[str, Any],
    dns: DnsResult | None,
    file=sys.stdout,
) -> None:
    """Export parsed data as JSON."""
    output: dict[str, Any] = {
        "meta": {
            "client_name": constants.client_info.get("name", ""),
            "client_version": constants.client_info.get("version", ""),
            "total_sources": len(entries),
            "log_format_version": constants.log_format_version,
        },
        "sources": [],
        "chains": [],
        "dns": None,
        "session_reuse": [],
    }

    # Sources
    for entry in sorted(entries.values(), key=lambda e: e.source_id):
        output["sources"].append({
            "source_id": entry.source_id,
            "source_type": constants.get_source_name(entry.source_type),
            "description": entry.description,
            "is_error": entry.is_error,
            "is_inactive": entry.is_inactive,
            "event_count": len(entry.entries),
        })

    # Chains from URL_REQUEST
    seen = set()
    for entry in find_events_by_type(entries, URL_REQUEST):
        sid = entry.source_id
        if sid in seen:
            continue
        chain = build_connection_chain(sid, entries)
        seen.add(sid)
        for m in _chain_members(chain):
            if m:
                seen.add(m.source_id)

        output["chains"].append({
            "url": chain.url_request.description if chain.url_request else None,
            "source_id": sid,
            "five_tuple": asdict(chain.five_tuple),
            "members": [
                {"type": constants.get_source_name(m.source_type),
                 "id": m.source_id,
                 "description": m.description}
                for m in _chain_members(chain) if m
            ],
        })

    # DNS
    if dns:
        output["dns"] = {
            "active": dns.active_entries,
            "expired": dns.expired_entries,
            "entries": [
                {
                    "hostname": e.hostname,
                    "addresses": e.addresses or e.ip_endpoints,
                    "ttl": e.ttl,
                    "error": e.error_name if e.error else None,
                    "expired": e.is_expired,
                }
                for e in dns.cache_entries
            ],
        }

    # Session reuse
    spdy = polled_data.get("spdySessionInfo") or []
    for s in spdy:
        aliases = s.get("aliases") or []
        if aliases:
            output["session_reuse"].append({
                "protocol": "HTTP2",
                "host": s.get("host_port_pair", ""),
                "aliases": aliases,
                "source_id": s.get("source_id", 0),
            })

    json.dump(output, file, indent=2, ensure_ascii=False, default=str)


def print_domain_analysis(
    entries: dict[int, SourceEntry],
    domain: str,
    file=sys.stdout,
) -> None:
    """Print domain analysis grouped by name, site, and relation."""
    from .domain_analyzer import analyze_domain

    results = analyze_domain(entries, domain)

    print(f"\n{'=' * 80}", file=file)
    print(f"  Domain Analysis: {domain}", file=file)
    print(f"{'=' * 80}", file=file)

    if not results:
        print(f"  (no connections found for '{domain}')", file=file)
        return

    for group in results:
        print(f"\n  [{group.relation.upper()}] {group.name}", file=file)
        print(f"  Site:       {group.site}", file=file)
        print(f"  Connections: {group.connection_num}", file=file)
        print(f"  Addresses:", file=file)
        for detail in group.connection_detail:
            local = detail.get("local_address", "") or "*"
            remote = detail.get("remote_address", "") or "*"
            print(f"    {local}  ->  {remote}", file=file)


def export_domain_json(
    entries: dict[int, SourceEntry],
    domain: str,
    file=sys.stdout,
) -> None:
    """Export domain analysis as JSON."""
    from .domain_analyzer import analyze_domain
    import json as _json

    results = analyze_domain(entries, domain)
    output = []
    for group in results:
        output.append({
            "name": group.name,
            "site": group.site,
            "relation": group.relation,
            "connection_num": group.connection_num,
            "connection_detail": group.connection_detail,
        })
    _json.dump(output, file, indent=2, ensure_ascii=False, default=str)


def _chain_members(c: ConnectionChain):
    """All non-None members of a chain in order."""
    return [
        c.url_request, c.http_stream_job, c.http_stream_job_controller,
        c.pool_group, c.connect_job, c.socket,
        c.tcp_attempt, c.tls_attempt, c.ssl_connect,
        c.h2_session, c.quic_session, c.dns_transaction,
    ]
