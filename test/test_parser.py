"""Tests for netlog_parser using a synthetic NetLog JSON."""

import sys
import os

# Force UTF-8 output on Windows
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

# Ensure local package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from parser.constants import NetLogConstants
from parser.source_entry import SourceEntry
from parser.event_processor import process_events
from parser.dependency_graph import (
    build_connection_chain,
    trace_chain,
)
from parser.dns_resolver import extract_dns_info


def _make_event(time, event_type, phase, source_id, source_type,
                params=None, start_time=None):
    """Create a synthetic NetLog event."""
    e = {
        "time": str(time),
        "type": event_type,
        "phase": phase,
        "source": {
            "id": source_id,
            "type": source_type,
            "start_time": str(start_time or time),
        },
    }
    if params:
        e["params"] = params
    return e


def test_source_entry_description():
    """Test that description extraction works for each source type."""
    registry: dict[int, str] = {5: "www.example.com:443"}

    # URL_REQUEST
    e = _make_event(1000, 11, 2, 1, 1,
                     params={"url": "https://www.example.com/"})
    entry = SourceEntry(source_id=1, source_type=1)
    constants = NetLogConstants({})
    entry.feed(e, constants)
    assert entry.description == "https://www.example.com/", \
        f"URL_REQUEST description: {entry.description}"

    # TCP_STREAM_ATTEMPT
    e2 = _make_event(1000, 5, 2, 2, 20,
                      params={"ip_endpoint": "93.184.216.34:443"})
    entry2 = SourceEntry(source_id=2, source_type=20)
    entry2.feed(e2, constants)
    assert entry2.description == "93.184.216.34:443", \
        f"TCP_STREAM_ATTEMPT description: {entry2.description}"

    # SOCKET with source_dependency
    e3 = _make_event(1000, 3, 2, 3, 3,
                      params={"source_dependency": {"id": 5, "type": 2}})
    entry3 = SourceEntry(source_id=3, source_type=3)
    entry3.feed(e3, constants)
    entry3.description = entry3._extract_description(constants, registry)
    assert entry3.description == "www.example.com:443", \
        f"SOCKET (via dep) description: {entry3.description}"

    print("  ✓ source_entry descriptions pass")


def test_five_tuple():
    """Test five-tuple extraction from parsed IP:port strings."""
    from parser.dependency_graph import _parse_ip_port

    # IPv4
    assert _parse_ip_port("93.184.216.34:443") == ("93.184.216.34", 443)
    assert _parse_ip_port("8.8.8.8:53") == ("8.8.8.8", 53)
    assert _parse_ip_port("") is None

    # IPv6
    assert _parse_ip_port("[::1]:443") == ("::1", 443)
    assert _parse_ip_port("[2001:db8::1]:8443") == ("2001:db8::1", 8443)

    print("  ✓ five-tuple parsing pass")


def test_event_grouping():
    """Test that events with the same source.id are grouped."""
    raw_constants = {
        "logFormatVersion": 1,
        "timeTickOffset": "1329000000000",
        "logEventTypes": {"REQUEST_ALIVE": 0, "URL_REQUEST_START_JOB": 11},
        "logSourceType": {"URL_REQUEST": 1},
        "logEventPhase": {"PHASE_BEGIN": 0, "PHASE_END": 1, "PHASE_NONE": 2},
        "clientInfo": {"name": "test"},
    }

    events = [
        _make_event(1000, 0, 0, 42, 1, params={"url": "https://a.com/"}),
        _make_event(1100, 11, 2, 42, 1),
        _make_event(1200, 0, 1, 42, 1),  # END
        _make_event(1000, 0, 0, 99, 1, params={"url": "https://b.com/"}),
    ]

    constants = NetLogConstants(raw_constants)
    entries = process_events(events, constants)

    assert len(entries) == 2, f"Expected 2 entries, got {len(entries)}"
    assert 42 in entries
    assert 99 in entries
    assert len(entries[42].entries) == 3
    assert len(entries[99].entries) == 1
    assert entries[42].description == "https://a.com/"
    assert entries[99].description == "https://b.com/"
    assert entries[42].is_inactive  # END phase seen
    assert not entries[99].is_inactive  # only BEGIN seen

    print("  ✓ event grouping pass")


def test_dependency_chain():
    """Test dependency chain tracing through source_dependency."""
    raw_constants = {
        "logFormatVersion": 1,
        "timeTickOffset": "1329000000000",
        "logEventTypes": {
            "REQUEST_ALIVE": 0, "URL_REQUEST_START_JOB": 11,
            "TCP_CONNECT": 4, "SOCKET_ALIVE": 3,
        },
        "logSourceType": {
            "URL_REQUEST": 1, "TRANSPORT_CONNECT_JOB": 2,
            "SOCKET": 3, "TCP_STREAM_ATTEMPT": 20,
        },
        "logEventPhase": {"PHASE_BEGIN": 0, "PHASE_END": 1, "PHASE_NONE": 2},
        "clientInfo": {"name": "test"},
    }

    events = [
        # URL_REQUEST → depends on HTTP_STREAM_JOB
        _make_event(1000, 0, 0, 100, 1,
                     params={"url": "https://www.example.com/",
                             "source_dependency": {"id": 200, "type": 5}}),
        # HTTP_STREAM_JOB → depends on connect job
        _make_event(1100, 21, 2, 200, 5,
                     params={"url": "https://www.example.com/",
                             "source_dependency": {"id": 300, "type": 2}}),
        # TRANSPORT_CONNECT_JOB
        _make_event(1050, 3, 0, 300, 2,
                     params={"group_id": "www.example.com:443"}),
        # SOCKET → depends on connect job
        _make_event(1200, 3, 0, 400, 3,
                     params={"source_dependency": {"id": 300, "type": 2}}),
        # TCP_STREAM_ATTEMPT → depends on SOCKET
        _make_event(1250, 5, 2, 500, 20,
                     params={"ip_endpoint": "93.184.216.34:443",
                             "source_dependency": {"id": 400, "type": 3}}),
    ]

    constants = NetLogConstants(raw_constants)
    entries = process_events(events, constants)

    # Trace from URL_REQUEST (100)
    chain = trace_chain(100, entries)
    chain_ids = [e.source_id for e in chain]
    assert 100 in chain_ids, f"URL_REQUEST (100) not in chain: {chain_ids}"

    # Build structured chain
    cc = build_connection_chain(100, entries)
    assert cc.url_request is not None, "url_request missing"
    assert cc.url_request.description == "https://www.example.com/"
    assert cc.connect_job is not None, "connect_job missing"
    assert cc.connect_job.description == "www.example.com:443"

    # Trace from TCP stream attempt (500)
    chain500 = trace_chain(500, entries)
    chain500_ids = [e.source_id for e in chain500]
    assert 400 in chain500_ids, f"SOCKET (400) not in chain from TCP: {chain500_ids}"

    cc500 = build_connection_chain(500, entries)
    assert cc500.tcp_attempt is not None
    assert cc500.tcp_attempt.description == "93.184.216.34:443"
    assert cc500.socket is not None
    assert cc500.five_tuple.dst_ip == "93.184.216.34"
    assert cc500.five_tuple.dst_port == 443

    print("  ✓ dependency chain pass")


def test_dns_extraction():
    """Test DNS cache entry extraction."""
    polled_data = {
        "hostResolverInfo": {
            "cache": {
                "capacity": 100,
                "network_changes": 2,
                "entries": [
                    {
                        "hostname": "www.example.com",
                        "address_family": 1,
                        "addresses": ["93.184.216.34"],
                        "ip_endpoints": [{"address": "93.184.216.34", "port": 0}],
                        "ttl": 300,
                        "expiration": "1329000500000",
                        "network_anonymization_key": "example.com",
                        "network_changes": 2,
                    },
                    {
                        "hostname": "bad.example.com",
                        "address_family": 1,
                        "error": -105,
                        "ttl": 0,
                        "expiration": "1329000400000",
                        "network_changes": 2,
                    },
                ],
            },
        },
    }

    constants = NetLogConstants({
        "logFormatVersion": 1,
        "timeTickOffset": "1329000000000",
        "netError": {"ERR_NAME_NOT_RESOLVED": -105},
    })

    dns = extract_dns_info(polled_data, constants)
    assert dns is not None
    assert dns.cache_capacity == 100
    assert len(dns.cache_entries) == 2
    assert dns.cache_entries[0].hostname == "www.example.com"
    assert dns.cache_entries[0].addresses == ["93.184.216.34"]
    assert not dns.cache_entries[0].is_expired
    assert dns.cache_entries[1].error == -105
    assert dns.cache_entries[1].error_name == "ERR_NAME_NOT_RESOLVED"
    # This one should be expired (network_changes 2 vs total 2 → equal, NOT expired)
    # Actually: expired if entry.network_changes < total_network_changes
    assert dns.cache_entries[1].is_expired  # expiration is before log date
    assert dns.active_entries == 1
    assert dns.expired_entries == 1

    print("  ✓ DNS extraction pass")


def test_ipv6_parse():
    """Test IPv6 address parsing for five-tuple."""
    from parser.dependency_graph import _parse_ip_port

    assert _parse_ip_port("[2001:db8:85a3::8a2e:370:7334]:443") == \
        ("2001:db8:85a3::8a2e:370:7334", 443)
    assert _parse_ip_port("[::]:0") == ("::", 0)

    print("  ✓ IPv6 parsing pass")


def test_error_tracking():
    """Test that net_error triggers is_error flag."""
    raw_constants = {
        "logFormatVersion": 1,
        "timeTickOffset": "0",
        "logEventTypes": {"REQUEST_ALIVE": 0},
        "logSourceType": {"URL_REQUEST": 1},
        "logEventPhase": {"PHASE_BEGIN": 0},
        "clientInfo": {},
    }

    # Error event
    events = [
        _make_event(1000, 0, 0, 1, 1,
                     params={"url": "https://fail.example.com/",
                             "net_error": -105}),
    ]

    constants = NetLogConstants(raw_constants)
    entries = process_events(events, constants)

    assert entries[1].is_error, f"Expected is_error=True, got {entries[1].is_error}"

    # Non-error event
    events2 = [
        _make_event(1000, 0, 0, 2, 1,
                     params={"url": "https://ok.example.com/",
                             "net_error": 0}),
    ]
    entries2 = process_events(events2, constants)
    assert not entries2[2].is_error, f"Expected is_error=False"

    print("  ✓ error tracking pass")


if __name__ == "__main__":
    print("Running netlog_parser tests...\n")
    test_source_entry_description()
    test_five_tuple()
    test_event_grouping()
    test_dependency_chain()
    test_dns_extraction()
    test_ipv6_parse()
    test_error_tracking()
    print("\n✓ All tests passed!")
