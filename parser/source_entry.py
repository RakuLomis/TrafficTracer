"""SourceEntry — groups all events sharing the same source.id."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .constants import (
    NetLogConstants,
    # Source type constants
    SRC_NONE,
    SRC_URL_REQUEST,
    SRC_TRANSPORT_CONNECT_JOB,
    SRC_SOCKET,
    SRC_HOST_RESOLVER_IMPL_JOB,
    SRC_HTTP_STREAM_JOB,
    SRC_CERT_VERIFIER_JOB,
    SRC_CERT_VERIFIER_TASK,
    SRC_SSL_CONNECT_JOB,
    SRC_SOCKS_CONNECT_JOB,
    SRC_HTTP_PROXY_CONNECT_JOB,
    SRC_WEB_SOCKET_TRANSPORT_CONNECT_JOB,
    SRC_HTTP_STREAM_JOB_CONTROLLER,
    SRC_BIDIRECTIONAL_STREAM,
    SRC_HTTP2_SESSION,
    SRC_QUIC_SESSION,
    SRC_QUIC_SESSION_POOL_JOB,
    SRC_HTTP_PIPELINED_CONNECTION,
    SRC_PROXY_CLIENT_SOCKET,
    SRC_UDP_SOCKET,
    SRC_TCP_STREAM_ATTEMPT,
    SRC_TLS_STREAM_ATTEMPT,
    SRC_DISK_CACHE_ENTRY,
    SRC_MEMORY_CACHE_ENTRY,
    SRC_ASYNC_HOST_RESOLVER_REQUEST,
    SRC_DNS_TRANSACTION,
    SRC_DNS_OVER_HTTPS,
    SRC_DOWNLOAD,
    SRC_FILESTREAM,
    SRC_DOH_URL_REQUEST,
    SRC_WEB_TRANSPORT_CLIENT,
    SRC_HTTP_STREAM_POOL_GROUP,
    SRC_HTTP_STREAM_POOL_JOB,
    SRC_HTTP_STREAM_POOL_ATTEMPT_MANAGER,
    SRC_HTTP_STREAM_POOL_QUIC_TASK,
    SRC_HOST_RESOLVER_IMPL_PROC_TASK,
    # Event type constants
    EVT_HTTP_CACHE_OPEN_ENTRY,
    EVT_UDP_CONNECT,
    EVT_IPV6_PROBE_RUNNING,
    EVT_SOCKET_POOL_CONNECT_JOB_CREATED,
    EVT_CERT_VERIFY_PROC,
    EVT_DOWNLOAD_FILE_RENAMED,
    EVT_DOWNLOAD_FILE_OPENED,
    EVT_DOWNLOAD_ITEM_ACTIVE,
    EVT_FILE_STREAM_OPEN,
)


@dataclass
class SourceEntry:
    """A group of log events with the same source.id.

    Mirrors the logic in netlog_viewer/netlog_viewer/source_entry.js.
    """

    source_id: int
    source_type: int
    entries: list[dict[str, Any]] = field(default_factory=list)

    # Extracted metadata
    description: str = ""
    is_error: bool = False
    is_inactive: bool = True

    # First event that best describes this source.
    start_entry: dict[str, Any] | None = None

    def __post_init__(self):
        self._seen_start_entry = False

    def feed(self, event: dict[str, Any], constants: NetLogConstants) -> None:
        """Process a new log event for this source."""
        params = event.get("params") or {}
        phase = event.get("phase", 2)  # PHASE_NONE
        event_type = event.get("type", 0)

        # Track inactive/active state (BEGIN → active, END → inactive)
        if phase == 0:  # PHASE_BEGIN
            self.is_inactive = False

        if self.entries:
            first = self.entries[0]
            if not self.is_inactive and phase == 1 and event_type == first.get("type"):
                self.is_inactive = True

        # Track error status from net_error param
        net_error_code = params.get("net_error")
        if net_error_code and net_error_code != 0:
            if event_type != EVT_HTTP_CACHE_OPEN_ENTRY or net_error_code != -2:
                self.is_error = True

        self.entries.append(event)

        # Determine start_entry (the event that best describes this source)
        self.start_entry = self._find_start_entry()

        # Update description
        self.description = self._extract_description(constants)

    def _find_start_entry(self) -> dict[str, Any] | None:
        """Find the entry that best describes this source.

        Mirrors SourceEntry.getStartEntry_() logic.
        """
        if not self.entries:
            return None

        source_type = self.entries[0]["source"]["type"]

        if source_type == SRC_FILESTREAM:
            for e in self.entries:
                if e.get("type") == EVT_FILE_STREAM_OPEN:
                    return e

        if source_type == SRC_DOWNLOAD:
            for e in reversed(self.entries):
                if e.get("type") == EVT_DOWNLOAD_FILE_RENAMED and e.get("phase") != 1:
                    return e
            for e in self.entries:
                if e.get("type") == EVT_DOWNLOAD_FILE_OPENED:
                    return e
                if e.get("type") == EVT_DOWNLOAD_ITEM_ACTIVE:
                    return e

        # HTTP_STREAM_JOB and SOCKET: prefer event with group_id (contains
        # the annotated name with same_site/cross_site classification).
        if source_type in (SRC_HTTP_STREAM_JOB, SRC_SOCKET):
            for e in self.entries:
                gid = (e.get("params") or {}).get("group_id")
                if isinstance(gid, str):
                    return e

        # HTTP_PROXY_CONNECT_JOB: prefer event with remote_address for a
        # meaningful description.
        if source_type == SRC_HTTP_PROXY_CONNECT_JOB:
            for e in self.entries:
                p = e.get("params") or {}
                if p.get("remote_address"):
                    return e

        if len(self.entries) >= 2:
            e2 = self.entries[1]
            if e2.get("type") in (EVT_UDP_CONNECT, EVT_IPV6_PROBE_RUNNING,
                                  EVT_SOCKET_POOL_CONNECT_JOB_CREATED, EVT_CERT_VERIFY_PROC):
                return e2

        return self.entries[0]

    def _extract_description(self, constants: NetLogConstants,
                             registry: dict[int, str] | None = None) -> str:
        """Extract a human-readable description based on source type and params.

        Mirrors SourceEntry.updateDescription_() in source_entry.js.
        """
        if not self.start_entry:
            return ""

        e = self.start_entry
        source_type = e["source"]["type"]
        params = e.get("params") or {}

        if source_type == SRC_NONE:
            return constants.get_event_name(e["type"])

        stype = source_type

        if stype in (SRC_URL_REQUEST, SRC_DOH_URL_REQUEST, SRC_BIDIRECTIONAL_STREAM):
            return params.get("url", "")

        # HTTP_STREAM_JOB / CONTROLLER: prefer group_id (contains same_site/cross_site annotation)
        # over plain url param. Format: "URL <site relation>"
        if stype in (SRC_HTTP_STREAM_JOB, SRC_HTTP_STREAM_JOB_CONTROLLER):
            gid = params.get("group_id")
            if isinstance(gid, str):
                return gid
            return params.get("url", "")

        if stype in (SRC_TRANSPORT_CONNECT_JOB, SRC_SSL_CONNECT_JOB,
                     SRC_SOCKS_CONNECT_JOB, SRC_HTTP_PROXY_CONNECT_JOB,
                     SRC_WEB_SOCKET_TRANSPORT_CONNECT_JOB):
            gid = params.get("group_id")
            if isinstance(gid, str):
                return gid
            gname = params.get("group_name")
            if isinstance(gname, str):
                return gname
            # Fallback: use remote_address for proxy connect jobs
            remote = params.get("remote_address")
            if isinstance(remote, str):
                return remote
            return ""

        if stype == SRC_TCP_STREAM_ATTEMPT:
            return params.get("ip_endpoint", "")

        if stype == SRC_TLS_STREAM_ATTEMPT:
            return params.get("host_port", "")

        if stype in (SRC_HTTP_STREAM_POOL_GROUP, SRC_HTTP_STREAM_POOL_JOB):
            sk = params.get("stream_key")
            if isinstance(sk, dict) and isinstance(sk.get("destination"), str):
                return sk["destination"]
            return ""

        if stype == SRC_HTTP_STREAM_POOL_ATTEMPT_MANAGER:
            sd = params.get("source_dependency")
            if isinstance(sd, dict) and sd.get("id") is not None:
                return _parent_description(sd["id"], registry or {})
            sk = params.get("stream_key")
            if isinstance(sk, dict) and isinstance(sk.get("destination"), str):
                return sk["destination"]
            return ""

        if stype == SRC_HTTP_STREAM_POOL_QUIC_TASK:
            sd = params.get("source_dependency")
            if isinstance(sd, dict) and sd.get("id") is not None:
                return _parent_description(sd["id"], registry or {})
            return ""

        if stype in (SRC_HOST_RESOLVER_IMPL_JOB, SRC_HOST_RESOLVER_IMPL_PROC_TASK):
            return params.get("host", "")

        if stype in (SRC_ASYNC_HOST_RESOLVER_REQUEST, SRC_DNS_TRANSACTION,
                     SRC_DNS_OVER_HTTPS):
            return params.get("hostname", "")

        if stype in (SRC_DISK_CACHE_ENTRY, SRC_MEMORY_CACHE_ENTRY):
            return params.get("key", "")

        if stype in (SRC_CERT_VERIFIER_JOB, SRC_CERT_VERIFIER_TASK):
            return params.get("host", "")

        if stype in (SRC_QUIC_SESSION, SRC_QUIC_SESSION_POOL_JOB):
            return params.get("host", "")

        if stype == SRC_HTTP2_SESSION:
            host = params.get("host", "")
            proxy = params.get("proxy", "")
            return f"{host} ({proxy})" if proxy else host

        if stype == SRC_HTTP_PIPELINED_CONNECTION:
            return params.get("host_and_port", "")

        if stype in (SRC_SOCKET, SRC_PROXY_CLIENT_SOCKET):
            sd = params.get("source_dependency")
            if isinstance(sd, dict) and sd.get("id") is not None:
                return _parent_description(sd["id"], registry or {})
            return ""

        if stype == SRC_UDP_SOCKET:
            addr = params.get("address", "")
            sd = params.get("source_dependency")
            if isinstance(sd, dict) and sd.get("id") is not None:
                parent_desc = _parent_description(sd["id"], registry or {})
                if parent_desc:
                    return f"{addr} [{parent_desc}]"
            return addr

        if stype == SRC_WEB_TRANSPORT_CLIENT:
            return params.get("url", "")

        return ""


def _parent_description(parent_id: int, registry: dict[int, str]) -> str:
    return registry.get(parent_id, "")
