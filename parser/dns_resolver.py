"""DNS resolution record extraction."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .constants import NetLogConstants


@dataclass
class DnsCacheEntry:
    """A single DNS cache entry from the host resolver cache."""

    hostname: str
    addresses: list[str]          # Resolved IPv4/IPv6 addresses
    ip_endpoints: list[str]        # "IP:port" format endpoints
    address_family: str            # "ADDRESS_FAMILY_IPV4" etc.
    ttl: int                       # Time-to-live in seconds
    expiration_ticks: str          # Raw expiration time tick
    error: int | None = None       # net_error code, if resolution failed
    error_name: str = ""
    network_anonymization_key: str = ""
    network_changes: int = 0
    is_expired: bool = False


@dataclass
class DnsResult:
    """Complete DNS resolution information from the log."""

    cache_capacity: int = 0
    network_changes: int = 0
    active_entries: int = 0
    expired_entries: int = 0
    cache_entries: list[DnsCacheEntry] = field(default_factory=list)
    dns_config: dict[str, Any] = field(default_factory=dict)


def extract_dns_info(
    polled_data: dict[str, Any],
    constants: NetLogConstants,
) -> DnsResult | None:
    """Extract DNS resolver cache information from polled data.

    The hostResolverInfo is only present in live-capture dumps, not in
    --log-net-log exports.
    """
    host_info = polled_data.get("hostResolverInfo")
    if not isinstance(host_info, dict):
        return None

    result = DnsResult()
    cache = host_info.get("cache")
    if isinstance(cache, dict):
        result.cache_capacity = cache.get("capacity", 0)
        result.network_changes = cache.get("network_changes", 0)

        log_date_ms = constants.ticks_to_unix_ms(
            _last_tick(cache.get("entries", []))
        )

        for e in cache.get("entries") or []:
            entry = _parse_cache_entry(e, constants, result.network_changes,
                                        log_date_ms)
            result.cache_entries.append(entry)
            if entry.is_expired:
                result.expired_entries += 1
            else:
                result.active_entries += 1

    result.dns_config = host_info.get("dns_config") or {}

    return result


def _parse_cache_entry(
    raw: dict[str, Any],
    constants: NetLogConstants,
    total_network_changes: int,
    log_date_ms: float,
) -> DnsCacheEntry:
    entry = DnsCacheEntry(
        hostname=raw.get("hostname", ""),
        addresses=raw.get("addresses") or [],
        ip_endpoints=(
            [f"{ep}" for ep in raw["ip_endpoints"]]
            if raw.get("ip_endpoints")
            else []
        ),
        address_family=_family_name(raw.get("address_family", 0)),
        ttl=raw.get("ttl", 0),
        expiration_ticks=raw.get("expiration", "0"),
        error=raw.get("net_error") or raw.get("error"),
        network_changes=raw.get("network_changes", 0),
    )

    # Network Anonymization Key (M108+) vs Network Isolation Key (pre-M108)
    nak = raw.get("network_anonymization_key")
    if nak is not None:
        entry.network_anonymization_key = str(nak)
    else:
        entry.network_anonymization_key = str(raw.get("network_isolation_key", ""))

    # Check if expired.
    # An entry is expired if:
    #  - Its TTL has elapsed (log time > expiration time), OR
    #  - The network has changed since the entry was cached (more recent
    #    network_changes on the cache means this entry belongs to a stale
    #    network configuration). When entry.network_changes equals
    #    total_network_changes, the entry was refreshed after the last
    #    network event and remains valid.
    if entry.error:
        entry.error_name = constants.get_net_error_name(entry.error)
    exp_ms = constants.ticks_to_unix_ms(entry.expiration_ticks)
    if log_date_ms > exp_ms or entry.network_changes < total_network_changes:
        entry.is_expired = True

    return entry


def _family_name(family: int) -> str:
    names = {0: "UNSPEC", 1: "IPV4", 2: "IPV6"}
    return names.get(family, f"ADDRESS_FAMILY_{family}")


def _last_tick(entries: list[dict[str, Any]]) -> str:
    """Get the latest expiration tick from cache entries."""
    latest = "0"
    for e in entries:
        t = e.get("expiration", "0")
        if float(t) > float(latest):
            latest = t
    return latest
