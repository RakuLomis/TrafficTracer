"""Dependency graph — trace source_dependency chains and extract five-tuples."""

from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

_checkpoint = ContextVar("dependency_checkpoint", default=None)


@contextmanager
def dependency_checkpoints(callback):
    # Entries are immutable during one chain traversal. Cache only properties
    # independent of visited/depth; never cache a path score by source ID.
    token = _checkpoint.set([callback, 0, {}, {}])
    try:
        yield
    finally:
        _checkpoint.reset(token)


def _check_traversal():
    tracker = _checkpoint.get()
    if tracker is not None:
        tracker[1] += 1
        if tracker[1] % 256 == 1:
            tracker[0]()

from .source_entry import SourceEntry
from .constants import (
    SRC_URL_REQUEST,
    SRC_TRANSPORT_CONNECT_JOB,
    SRC_SOCKET,
    SRC_HOST_RESOLVER_IMPL_JOB,
    SRC_ASYNC_HOST_RESOLVER_REQUEST,
    SRC_DNS_OVER_HTTPS,
    SRC_HOST_RESOLVER_IMPL_PROC_TASK,
    SRC_HTTP_STREAM_JOB,
    SRC_SSL_CONNECT_JOB,
    SRC_SOCKS_CONNECT_JOB,
    SRC_HTTP_PROXY_CONNECT_JOB,
    SRC_WEB_SOCKET_TRANSPORT_CONNECT_JOB,
    SRC_HTTP_STREAM_JOB_CONTROLLER,
    SRC_HTTP2_SESSION,
    SRC_QUIC_SESSION,
    SRC_PROXY_CLIENT_SOCKET,
    SRC_UDP_SOCKET,
    SRC_TCP_STREAM_ATTEMPT,
    SRC_TLS_STREAM_ATTEMPT,
    SRC_DNS_TRANSACTION,
    SRC_HTTP_STREAM_POOL_GROUP,
    SRC_HTTP_STREAM_POOL_JOB,
    SRC_HTTP_STREAM_POOL_ATTEMPT_MANAGER,
    SRC_HTTP_STREAM_POOL_QUIC_TASK,
    SRC_HTTP_PIPELINED_CONNECTION,
    EVT_SSL_CONNECT,
)

# Re-export under short names for backward compatibility
URL_REQUEST = SRC_URL_REQUEST
TRANSPORT_CONNECT_JOB = SRC_TRANSPORT_CONNECT_JOB
SOCKET = SRC_SOCKET
HOST_RESOLVER_IMPL_JOB = SRC_HOST_RESOLVER_IMPL_JOB
HTTP_STREAM_JOB = SRC_HTTP_STREAM_JOB
SSL_CONNECT_JOB = SRC_SSL_CONNECT_JOB
SOCKS_CONNECT_JOB = SRC_SOCKS_CONNECT_JOB
HTTP_PROXY_CONNECT_JOB = SRC_HTTP_PROXY_CONNECT_JOB
HTTP2_SESSION = SRC_HTTP2_SESSION
QUIC_SESSION = SRC_QUIC_SESSION
PROXY_CLIENT_SOCKET = SRC_PROXY_CLIENT_SOCKET
UDP_SOCKET = SRC_UDP_SOCKET
TCP_STREAM_ATTEMPT = SRC_TCP_STREAM_ATTEMPT
TLS_STREAM_ATTEMPT = SRC_TLS_STREAM_ATTEMPT
DNS_TRANSACTION = SRC_DNS_TRANSACTION
HTTP_STREAM_POOL_GROUP = SRC_HTTP_STREAM_POOL_GROUP
HTTP_STREAM_POOL_JOB = SRC_HTTP_STREAM_POOL_JOB
HTTP_STREAM_POOL_ATTEMPT_MANAGER = SRC_HTTP_STREAM_POOL_ATTEMPT_MANAGER
HTTP_STREAM_POOL_QUIC_TASK = SRC_HTTP_STREAM_POOL_QUIC_TASK
SSL_CONNECT = EVT_SSL_CONNECT

# Source types we consider "leaf" nodes for five-tuple extraction
_LEAF_TYPES = {
    SOCKET, PROXY_CLIENT_SOCKET, TCP_STREAM_ATTEMPT, TLS_STREAM_ATTEMPT,
    UDP_SOCKET, QUIC_SESSION, HTTP2_SESSION,
}

_DNS_SOURCE_TYPES = {
    HOST_RESOLVER_IMPL_JOB, SRC_ASYNC_HOST_RESOLVER_REQUEST, DNS_TRANSACTION,
    SRC_DNS_OVER_HTTPS, SRC_HOST_RESOLVER_IMPL_PROC_TASK,
}

_BUSINESS_TRANSPORT_TYPES = {
    TRANSPORT_CONNECT_JOB, SOCKET, SSL_CONNECT_JOB, SOCKS_CONNECT_JOB,
    HTTP_PROXY_CONNECT_JOB, SRC_WEB_SOCKET_TRANSPORT_CONNECT_JOB,
    HTTP2_SESSION, QUIC_SESSION, PROXY_CLIENT_SOCKET,
    TCP_STREAM_ATTEMPT, TLS_STREAM_ATTEMPT,
}


@dataclass
class FiveTuple:
    """TCP/IP five-tuple."""
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None  # "TCP", "UDP", "QUIC", "HTTP2"
    # The IP transport is independent from the application/session protocol.
    # A NetLog chain may contain a failed QUIC attempt followed by a successful
    # TCP fallback; the socket carrying the tuple remains authoritative.
    network: str | None = None  # "tcp" or "udp"
    attempted_protocols: list[str] = field(default_factory=list)
    # Optional audit evidence for endpoint recovery performed after the
    # dependency walk. Keeping the complete pair and its source together
    # prevents a later TCP fallback from donating one endpoint to QUIC.
    endpoint_provenance: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        src = f"{self.src_ip or '*'}:{self.src_port or '*'}"
        dst = f"{self.dst_ip or '*'}:{self.dst_port or '*'}"
        return f"({src} -> {dst}, {self.protocol or '?'})"


@dataclass
class ConnectionChain:
    """A full connection dependency chain from URL_REQUEST down to TCP."""

    url_request: SourceEntry | None = None
    http_stream_job: SourceEntry | None = None
    http_stream_job_controller: SourceEntry | None = None
    connect_job: SourceEntry | None = None
    socket: SourceEntry | None = None
    tcp_attempt: SourceEntry | None = None
    tls_attempt: SourceEntry | None = None
    ssl_connect: SourceEntry | None = None
    dns_transaction: SourceEntry | None = None
    h2_session: SourceEntry | None = None
    quic_session: SourceEntry | None = None
    udp_socket: SourceEntry | None = None
    pool_group: SourceEntry | None = None

    # Extra info
    five_tuple: FiveTuple = field(default_factory=FiveTuple)

    def is_complete(self) -> bool:
        """A chain is 'useful' if it has at least a URL request or a socket."""
        return self.url_request is not None or self.socket is not None


@dataclass
class SessionReuse:
    """HTTP/2 or QUIC session that served multiple domains."""

    source_id: int
    session_host: str
    protocol: str  # "HTTP2" or "QUIC"
    aliases: list[str]
    active_streams: int
    max_concurrent_streams: int


def extract_deps_from_event(event: dict[str, Any]) -> int | None:
    """Get the source_dependency.id from an event's params, if any."""
    params = event.get("params")
    if not isinstance(params, dict):
        return None
    sd = params.get("source_dependency")
    if isinstance(sd, dict):
        return sd.get("id")
    return None


def _build_children_index(
    entries: dict[int, SourceEntry],
) -> dict[int, list[int]]:
    """Build a reverse index: parent_id -> list of child source_ids.

    Scans all events for source_dependency, and maps each dependency.target
    to the source that references it.
    """
    children: dict[int, list[int]] = {}
    for sid, entry in entries.items():
        seen_parents: set[int] = set()
        for event in entry.entries:
            parent_id = extract_deps_from_event(event)
            if parent_id is not None and parent_id != sid and parent_id not in seen_parents:
                children.setdefault(parent_id, []).append(sid)
                seen_parents.add(parent_id)
    return children


def trace_chain(
    source_id: int,
    entries: dict[int, SourceEntry],
    max_depth: int = 20,
) -> list[SourceEntry]:
    """Trace source_dependency links from source_id upward (toward ancestors).

    Returns the chain from the root (earliest ancestor) to source_id.
    Skips dependencies that would cause cycles (already-visited nodes) and
    continues checking later events in the entry for a valid parent.
    """
    chain: list[SourceEntry] = []
    visited: set[int] = set()
    current_id: int | None = source_id

    while current_id is not None and len(chain) < max_depth:
        if current_id in visited:
            break
        visited.add(current_id)

        entry = entries.get(current_id)
        if entry is None:
            break

        chain.append(entry)

        # A source may reference several competing attempts (for example a
        # failed QUIC/DNS branch and a successful HTTP/2 socket). Prefer the
        # path that contains concrete business transport evidence.
        candidates = [
            dep_id for dep_id in _dependency_ids(entry)
            if dep_id != entry.source_id and dep_id not in visited
        ]
        current_id = max(
            candidates,
            key=lambda dep_id: _dependency_path_score(
                dep_id, entries, visited=set(visited), max_depth=8,
            ),
            default=None,
        )

    chain.reverse()  # root first
    return chain


def _dependency_ids(entry: SourceEntry) -> list[int]:
    tracker = _checkpoint.get()
    cache = tracker[2] if tracker is not None else {}
    key = id(entry)
    if key in cache:
        return cache[key]
    result = list(dict.fromkeys(
        dep_id
        for event in entry.entries
        if (dep_id := extract_deps_from_event(event)) is not None
    ))
    cache[key] = result
    return result


def _dependency_path_score(
    source_id: int,
    entries: dict[int, SourceEntry],
    visited: set[int],
    max_depth: int,
) -> int:
    """Score a dependency branch by its strongest transport evidence."""
    _check_traversal()
    if source_id in visited or max_depth <= 0:
        return -10_000
    entry = entries.get(source_id)
    if entry is None:
        return -10_000
    visited.add(source_id)

    if entry.source_type in _DNS_SOURCE_TYPES:
        own_score = -1_000
    elif _entry_has_complete_endpoints(entry):
        own_score = 1_000
    elif entry.source_type in (SOCKET, PROXY_CLIENT_SOCKET):
        own_score = 600
    elif entry.source_type in (HTTP2_SESSION, QUIC_SESSION):
        own_score = 500
    elif entry.source_type in _BUSINESS_TRANSPORT_TYPES:
        own_score = 400
    elif entry.source_type in (HTTP_STREAM_JOB, SRC_HTTP_STREAM_JOB_CONTROLLER):
        own_score = 100
    else:
        own_score = 0

    # No node scores above 1,000 and every dependency edge costs 10.
    # Once that bound is reached, visiting other branches cannot change the
    # answer. Keep visited/depth semantics rather than caching by source ID.
    if own_score == 1_000:
        return own_score
    best = own_score
    for dep_id in _dependency_ids(entry):
        if dep_id not in visited:
            best = max(best, _dependency_path_score(
                dep_id, entries, visited=set(visited), max_depth=max_depth - 1,
            ) - 10)
            if best >= 990:
                break
    return best


def _entry_has_complete_endpoints(entry: SourceEntry) -> bool:
    tracker = _checkpoint.get()
    cache = tracker[3] if tracker is not None else {}
    key = id(entry)
    if key not in cache:
        cache[key] = _scan_complete_endpoints(entry)
    return cache[key]


def _scan_complete_endpoints(entry: SourceEntry) -> bool:
    for event in entry.entries:
        params = event.get("params") or {}
        if (
            isinstance(params.get("local_address"), str)
            and isinstance(params.get("remote_address"), str)
            and _parse_ip_port(params["local_address"])
            and _parse_ip_port(params["remote_address"])
        ):
            return True
    return False


def _find_downstream_leaves(
    source_id: int,
    children_index: dict[int, list[int]],
    entries: dict[int, SourceEntry],
    visited: set[int] | None = None,
    max_depth: int = 10,
) -> list[SourceEntry]:
    """Recursively find leaf-type entries (TCP, TLS, etc.) downstream."""
    _check_traversal()
    if visited is None:
        visited = set()
    if source_id in visited or max_depth <= 0:
        return []
    visited.add(source_id)

    results: list[SourceEntry] = []
    for child_id in children_index.get(source_id, []):
        child = entries.get(child_id)
        if child is None:
            continue
        if child.source_type in _LEAF_TYPES:
            results.append(child)
        # Recurse further (e.g. SOCKET -> TCP_STREAM_ATTEMPT)
        results.extend(
            _find_downstream_leaves(child_id, children_index, entries,
                                     visited, max_depth - 1)
        )
    return results


def build_connection_chain(
    source_id: int,
    entries: dict[int, SourceEntry],
    children_index: dict[int, list[int]] | None = None,
) -> ConnectionChain:
    """Build a structured connection chain starting from any source_id.

    Traces upward (ancestors) via source_dependency, then also searches
    downward (descendants) to find leaf endpoints like TCP_STREAM_ATTEMPT.
    """
    if children_index is None:
        children_index = _build_children_index(entries)

    chain_entries = trace_chain(source_id, entries)
    result = ConnectionChain()

    for entry in chain_entries:
        st = entry.source_type
        if st == URL_REQUEST:
            result.url_request = entry
        elif st == HTTP_STREAM_JOB:
            result.http_stream_job = entry
        elif st == SRC_HTTP_STREAM_JOB_CONTROLLER:
            result.http_stream_job_controller = entry
        elif st in (TRANSPORT_CONNECT_JOB, SSL_CONNECT_JOB,
                     SOCKS_CONNECT_JOB, HTTP_PROXY_CONNECT_JOB,
                     SRC_WEB_SOCKET_TRANSPORT_CONNECT_JOB):
            if result.connect_job is None:
                result.connect_job = entry
        elif st in (SOCKET, PROXY_CLIENT_SOCKET):
            if result.socket is None:
                result.socket = entry
        elif st == TCP_STREAM_ATTEMPT:
            result.tcp_attempt = entry
        elif st == TLS_STREAM_ATTEMPT:
            result.tls_attempt = entry
        elif st == HTTP2_SESSION:
            result.h2_session = entry
        elif st == QUIC_SESSION:
            result.quic_session = entry
        elif st in (HTTP_STREAM_POOL_GROUP, HTTP_STREAM_POOL_JOB,
                     HTTP_STREAM_POOL_ATTEMPT_MANAGER, HTTP_STREAM_POOL_QUIC_TASK):
            if result.pool_group is None:
                result.pool_group = entry
        elif st == DNS_TRANSACTION:
            result.dns_transaction = entry

    # Search downstream from every node in the chain for leaf endpoints.
    chain_ids = {e.source_id for e in chain_entries}
    for entry in chain_entries:
        # Allow the current entry as the starting point for the DFS
        start_visited = chain_ids - {entry.source_id}
        leaves = _find_downstream_leaves(entry.source_id, children_index,
                                          entries, start_visited, max_depth=8)
        for leaf in leaves:
            st = leaf.source_type
            if st == TCP_STREAM_ATTEMPT and result.tcp_attempt is None:
                result.tcp_attempt = leaf
            elif st == TLS_STREAM_ATTEMPT and result.tls_attempt is None:
                result.tls_attempt = leaf
            elif st in (HTTP2_SESSION,) and result.h2_session is None:
                result.h2_session = leaf
            elif st in (QUIC_SESSION,) and result.quic_session is None:
                result.quic_session = leaf
            elif st in (SOCKET, PROXY_CLIENT_SOCKET) and result.socket is None:
                result.socket = leaf
            elif (
                st == UDP_SOCKET
                and result.udp_socket is None
                and result.socket is None
                and result.tcp_attempt is None
                and result.tls_attempt is None
                and result.h2_session is None
            ):
                result.udp_socket = leaf

    # Check for SSL_CONNECT events within the socket entry
    if result.socket:
        for event in result.socket.entries:
            if event.get("type") == SSL_CONNECT:
                result.ssl_connect = result.socket
                break

    # Search downstream for address-bearing entries (HTTP_PROXY_CONNECT_JOB, etc.)
    # that carry local_address / remote_address in SSL_CONNECT events.
    address_entries: list[SourceEntry] = []
    for entry in chain_entries:
        for child_id in children_index.get(entry.source_id, []):
            if child_id in chain_ids:
                continue
            child = entries.get(child_id)
            if child is not None and child.source_type == SRC_HTTP_PROXY_CONNECT_JOB:
                if child not in address_entries:
                    address_entries.append(child)

    # Extract five-tuple — combine upstream chain + downstream leaves + address entries
    all_entries = list(chain_entries) + [
        e for e in [result.tcp_attempt, result.tls_attempt,
                     result.h2_session, result.quic_session,
                     result.udp_socket]
        if e is not None and e not in chain_entries
    ] + address_entries
    result.five_tuple = extract_five_tuple(all_entries)

    return result


def extract_five_tuple(chain: list[SourceEntry]) -> FiveTuple:
    """Extract five-tuple information from a dependency chain.

    Checks both SourceEntry descriptions (for old-style TCP/TLS entries)
    and raw event params (for SSL_CONNECT local_address/remote_address
    found in newer Chrome versions using HTTP_PROXY_CONNECT_JOB).
    """
    ft = FiveTuple()
    saw_tcp_transport = False
    saw_udp_transport = False
    saw_quic_attempt = False

    for entry in chain:
        st = entry.source_type

        if st == TCP_STREAM_ATTEMPT:
            saw_tcp_transport = True
            ip_port = entry.description  # e.g. "93.184.216.34:443"
            parsed = _parse_ip_port(ip_port)
            if parsed:
                ft.dst_ip, ft.dst_port = parsed
                ft.protocol = ft.protocol or "TCP"

        elif st == TLS_STREAM_ATTEMPT:
            hp = entry.description  # e.g. "example.com:443"
            parsed = _parse_ip_port(hp)
            if parsed:
                ft.dst_port = ft.dst_port or parsed[1]

        elif st == UDP_SOCKET:
            saw_udp_transport = True
            addr = entry.description  # e.g. "8.8.8.8:53"
            if " [" in addr:
                addr = addr.split(" [")[0]
            parsed = _parse_ip_port(addr)
            if parsed:
                ft.dst_ip = ft.dst_ip or parsed[0]
                ft.dst_port = ft.dst_port or parsed[1]
                ft.protocol = ft.protocol or "UDP"

        elif st == HTTP2_SESSION:
            saw_tcp_transport = True
            ft.protocol = "HTTP2"
        elif st == QUIC_SESSION or st == SRC_HTTP_STREAM_POOL_QUIC_TASK:
            saw_quic_attempt = True
            if "QUIC" not in ft.attempted_protocols:
                ft.attempted_protocols.append("QUIC")
            ft.protocol = "QUIC"

        elif st == URL_REQUEST:
            url = entry.description
            if url.startswith("https://"):
                ft.protocol = ft.protocol or "HTTPS"
            elif url.startswith("http://"):
                ft.protocol = ft.protocol or "HTTP"

        # Scan raw events for SSL_CONNECT / TCP_CONNECT address params.
        # Chrome 149+ uses HTTP_PROXY_CONNECT_JOB with SSL_CONNECT events
        # that carry local_address and remote_address.
        for event in entry.entries:
            _extract_address_from_event(event, ft, st)

    # Concrete socket evidence wins over retained session attempts. In
    # particular, a failed QUIC branch cannot turn a successful TCP fallback
    # tuple into UDP.
    if saw_tcp_transport:
        ft.network = "tcp"
    elif saw_udp_transport or saw_quic_attempt:
        ft.network = "udp"
    elif ft.protocol:
        ft.network = (
            "udp" if ft.protocol.lower().startswith(("udp", "quic")) else "tcp"
        )

    return ft


def _extract_address_from_event(
    event: dict[str, Any],
    ft: FiveTuple,
    source_type: int | None = None,
) -> None:
    """Pull local/remote address from an event's params into the FiveTuple."""
    params = event.get("params")
    if not isinstance(params, dict):
        return

    local = params.get("local_address")
    if isinstance(local, str):
        parsed = _parse_ip_port(local)
        if parsed:
            ft.src_ip = ft.src_ip or parsed[0]
            ft.src_port = ft.src_port or parsed[1]

    remote = params.get("remote_address")
    if isinstance(remote, str):
        parsed = _parse_ip_port(remote)
        if parsed:
            ft.dst_ip = ft.dst_ip or parsed[0]
            ft.dst_port = ft.dst_port or parsed[1]

    # Chromium QUIC_SESSION events expose the connected UDP endpoints as
    # self_address/peer_address rather than local_address/remote_address.
    # Restrict these aliases to QUIC business transports so similarly named
    # diagnostic fields cannot turn resolver activity into an HTTP flow.
    if source_type in (QUIC_SESSION, UDP_SOCKET, HTTP_STREAM_POOL_QUIC_TASK):
        self_address = params.get("self_address")
        if isinstance(self_address, str):
            parsed = _parse_ip_port(self_address)
            if parsed:
                ft.src_ip = ft.src_ip or parsed[0]
                ft.src_port = ft.src_port or parsed[1]

        peer_address = params.get("peer_address")
        if isinstance(peer_address, str):
            parsed = _parse_ip_port(peer_address)
            if parsed:
                ft.dst_ip = ft.dst_ip or parsed[0]
                ft.dst_port = ft.dst_port or parsed[1]

    # Resolver and UDP events use "address" for the DNS server. Only accept
    # this field from a source known to represent a business transport.
    if not ft.dst_ip and source_type in _BUSINESS_TRANSPORT_TYPES:
        addr = params.get("address")
        if isinstance(addr, str):
            parsed = _parse_ip_port(addr)
            if parsed:
                ft.dst_ip = ft.dst_ip or parsed[0]
                ft.dst_port = ft.dst_port or parsed[1]


def _parse_ip_port(s: str) -> tuple[str, int] | None:
    """Parse "host:port" or "[::1]:port" into (host, port)."""
    if not s:
        return None

    # IPv6 bracket notation: "[::1]:443"
    if s.startswith("["):
        idx = s.rfind("]:")
        if idx == -1:
            return None
        host = s[1:idx]
        port_str = s[idx + 2:]
    else:
        idx = s.rfind(":")
        if idx == -1:
            return None
        host = s[:idx]
        port_str = s[idx + 1:]

    try:
        port = int(port_str)
    except ValueError:
        return None

    return host, port
