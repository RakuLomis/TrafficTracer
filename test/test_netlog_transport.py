"""Tests for NetLog transport tracer."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import tempfile

from traffictracer.analyze.netlog_transport import trace_transport
from traffictracer.models import AttributedRequest, TransportConnection


def _make_netlog(events: list[dict]) -> str:
    netlog = {
        "constants": {
            "logFormatVersion": 1,
            "timeTickOffset": "1329000000000",
            "logSourceType": {
                "URL_REQUEST": 1, "TRANSPORT_CONNECT_JOB": 2,
                "SOCKET": 3, "HTTP_STREAM_JOB": 5,
                "HTTP_PROXY_CONNECT_JOB": 10, "TCP_STREAM_ATTEMPT": 20,
                "HTTP2_SESSION": 14, "HTTP_STREAM_JOB_CONTROLLER": 12,
                "HOST_RESOLVER_IMPL_JOB": 4, "DNS_TRANSACTION": 25,
                "UDP_SOCKET": 19,
            },
            "logEventPhase": {"PHASE_BEGIN": 0, "PHASE_END": 1, "PHASE_NONE": 2},
        },
        "events": events,
    }
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(netlog, f)
    return path


def test_trace_single_request():
    events = [
        {"time": "1000", "type": 0, "phase": 0,
         "source": {"id": 100, "type": 1},
         "params": {"url": "https://cdn.example.net/video.m4s",
                     "source_dependency": {"id": 200, "type": 5}}},
        {"time": "1100", "type": 21, "phase": 2,
         "source": {"id": 200, "type": 5},
         "params": {"group_id": "https://cdn.example.net <https://example.com cross_site>"}},
        {"time": "1200", "type": 50, "phase": 2,
         "source": {"id": 300, "type": 10},
         "params": {"local_address": "198.18.0.1:49812",
                     "remote_address": "1.2.3.4:443",
                     "source_dependency": {"id": 200, "type": 5}}},
    ]
    netlog_path = _make_netlog(events)

    requests = [
        AttributedRequest(
            request_id="1.1", target_id="T1", frame_id="F1",
            url="https://cdn.example.net/video.m4s",
            resource_type="Media", timestamp=100.0,
        ),
    ]

    conns = trace_transport(requests, netlog_path)
    os.unlink(netlog_path)

    assert len(conns) >= 1
    conn = conns[0]
    assert isinstance(conn, TransportConnection)
    assert conn.src_ip == "198.18.0.1"
    assert conn.src_port == 49812
    assert conn.dst_ip == "1.2.3.4"
    assert conn.dst_port == 443
    assert "1.1" in conn.request_ids


def test_trace_unknown_cdn_matched_by_url():
    """A CDN domain with no relation to the visit domain is still matched."""
    events = [
        {"time": "1000", "type": 0, "phase": 0,
         "source": {"id": 100, "type": 1},
         "params": {"url": "https://xyz.edge-provider.net/asset.js",
                     "source_dependency": {"id": 200, "type": 5}}},
        {"time": "1200", "type": 50, "phase": 2,
         "source": {"id": 300, "type": 10},
         "params": {"local_address": "198.18.0.1:50000",
                     "remote_address": "5.6.7.8:443",
                     "source_dependency": {"id": 200, "type": 5}}},
    ]
    netlog_path = _make_netlog(events)

    requests = [
        AttributedRequest(
            request_id="2.1", target_id="T1", frame_id="F1",
            url="https://xyz.edge-provider.net/asset.js",
            resource_type="Script", timestamp=200.0,
        ),
    ]

    conns = trace_transport(requests, netlog_path)
    os.unlink(netlog_path)

    assert len(conns) >= 1
    assert conns[0].dst_ip == "5.6.7.8"
    assert "2.1" in conns[0].request_ids


def test_different_urls_on_one_transport_are_merged_by_transport_source():
    events = [
        {"time": "1000", "type": 0, "phase": 0, "source": {"id": 100, "type": 1},
         "params": {"url": "https://cdn.example.net/a.js", "source_dependency": {"id": 200, "type": 5}}},
        {"time": "1010", "type": 0, "phase": 0, "source": {"id": 101, "type": 1},
         "params": {"url": "https://cdn.example.net/b.js", "source_dependency": {"id": 200, "type": 5}}},
        {"time": "1200", "type": 50, "phase": 2, "source": {"id": 300, "type": 10},
         "params": {"local_address": "198.18.0.1:49812", "remote_address": "1.2.3.4:443",
                    "source_dependency": {"id": 200, "type": 5}}},
    ]
    path = _make_netlog(events)
    requests = [
        AttributedRequest("1.1", "T", "F", "https://cdn.example.net/a.js", "Script", 100.0),
        AttributedRequest("1.2", "T", "F", "https://cdn.example.net/b.js", "Script", 100.1),
    ]
    try:
        connections = trace_transport(requests, path)
    finally:
        os.unlink(path)
    assert len(connections) == 1
    assert connections[0].netlog_source_id == 300
    assert connections[0].request_ids == ["1.1", "1.2"]
    assert connections[0].first_observed == 100.0


def test_trace_no_match():
    events = [
        {"time": "1000", "type": 0, "phase": 0,
         "source": {"id": 100, "type": 1},
         "params": {"url": "https://other.com/page"}},
    ]
    netlog_path = _make_netlog(events)

    requests = [
        AttributedRequest(
            request_id="3.1", target_id="T1", frame_id="F1",
            url="https://notfound.com/missing.js",
            resource_type="Script", timestamp=300.0,
        ),
    ]

    conns = trace_transport(requests, netlog_path)
    os.unlink(netlog_path)

    assert len(conns) == 0


def test_trace_multiple_requests_same_connection():
    """Two CDP requests matching the same NetLog URL_REQUEST share a connection."""
    events = [
        {"time": "1000", "type": 0, "phase": 0,
         "source": {"id": 100, "type": 1},
         "params": {"url": "https://api.example.com/data",
                     "source_dependency": {"id": 200, "type": 5}}},
        {"time": "1200", "type": 50, "phase": 2,
         "source": {"id": 300, "type": 10},
         "params": {"local_address": "198.18.0.1:60000",
                     "remote_address": "9.8.7.6:443",
                     "source_dependency": {"id": 200, "type": 5}}},
    ]
    netlog_path = _make_netlog(events)

    requests = [
        AttributedRequest(
            request_id="4.1", target_id="T1", frame_id="F1",
            url="https://api.example.com/data",
            resource_type="XHR", timestamp=400.0,
        ),
        AttributedRequest(
            request_id="4.2", target_id="T1", frame_id="F1",
            url="https://api.example.com/data",
            resource_type="Fetch", timestamp=400.1,
        ),
    ]

    conns = trace_transport(requests, netlog_path)
    os.unlink(netlog_path)

    assert len(conns) >= 1
    all_rids = set()
    for c in conns:
        all_rids.update(c.request_ids)
    assert "4.1" in all_rids
    assert "4.2" in all_rids


def test_query_occurrences_are_not_broadcast_to_every_transport():
    """Repeated paths retain one-to-one request occurrences across transports."""
    first = "https://media.example/videoplayback?rn=1"
    second = "https://media.example/videoplayback?rn=2"
    events = [
        {"time": "1000", "type": 0, "phase": 0,
         "source": {"id": 100, "type": 1},
         "params": {"url": first, "source_dependency": {"id": 200, "type": 5}}},
        {"time": "1010", "type": 0, "phase": 0,
         "source": {"id": 101, "type": 1},
         "params": {"url": second, "source_dependency": {"id": 201, "type": 5}}},
        {"time": "1020", "type": 50, "phase": 2,
         "source": {"id": 300, "type": 10},
         "params": {"local_address": "198.18.0.1:60362",
                     "remote_address": "198.18.0.56:443",
                     "source_dependency": {"id": 200, "type": 5}}},
        {"time": "1030", "type": 50, "phase": 2,
         "source": {"id": 301, "type": 10},
         "params": {"local_address": "198.18.0.1:60366",
                     "remote_address": "198.18.0.56:443",
                     "source_dependency": {"id": 201, "type": 5}}},
    ]
    path = _make_netlog(events)
    requests = [
        AttributedRequest("media.1", "T", "F", first, "Media", 100.0),
        AttributedRequest("media.2", "T", "F", second, "Media", 101.0),
    ]
    try:
        connections = trace_transport(requests, path)
    finally:
        os.unlink(path)

    assert len(connections) == 2
    by_port = {item.src_port: item.request_ids for item in connections}
    assert by_port == {60362: ["media.1"], 60366: ["media.2"]}

def test_dns_only_dependency_is_not_a_browser_transport():
    events = [
        {"time": "1000", "type": 0, "phase": 0, "source": {"id": 100, "type": 1},
         "params": {"url": "https://dns-only.example/", "source_dependency": {"id": 200, "type": 4}}},
        {"time": "1010", "type": 1, "phase": 2, "source": {"id": 200, "type": 4},
         "params": {"source_dependency": {"id": 300, "type": 25}}},
        {"time": "1020", "type": 1, "phase": 2, "source": {"id": 300, "type": 25},
         "params": {"source_dependency": {"id": 400, "type": 19}}},
        {"time": "1030", "type": 43, "phase": 2, "source": {"id": 400, "type": 19},
         "params": {"address": "127.0.0.53:53"}},
    ]
    path = _make_netlog(events)
    requests = [AttributedRequest("dns.1", "T", "F", "https://dns-only.example/", "Document", 1.0)]
    try:
        assert trace_transport(requests, path) == []
    finally:
        os.unlink(path)


def test_successful_socket_branch_wins_over_failed_dns_branch():
    events = [
        {"time": "1000", "type": 0, "phase": 0, "source": {"id": 100, "type": 1},
         "params": {"url": "https://cdn.example/asset.js", "source_dependency": {"id": 110, "type": 12}}},
        {"time": "1001", "type": 21, "phase": 2, "source": {"id": 110, "type": 12},
         "params": {"source_dependency": {"id": 120, "type": 5}}},
        {"time": "1002", "type": 21, "phase": 2, "source": {"id": 110, "type": 12},
         "params": {"source_dependency": {"id": 130, "type": 5}}},
        {"time": "1010", "type": 21, "phase": 2, "source": {"id": 120, "type": 5},
         "params": {"source_dependency": {"id": 140, "type": 4}}},
        {"time": "1011", "type": 1, "phase": 2, "source": {"id": 140, "type": 4},
         "params": {"source_dependency": {"id": 150, "type": 25}}},
        {"time": "1012", "type": 43, "phase": 2, "source": {"id": 150, "type": 25},
         "params": {"address": "127.0.0.53:53"}},
        {"time": "1020", "type": 21, "phase": 2, "source": {"id": 130, "type": 5},
         "params": {"source_dependency": {"id": 160, "type": 3}}},
        {"time": "1021", "type": 4, "phase": 2, "source": {"id": 160, "type": 3},
         "params": {"local_address": "198.18.0.1:42000", "remote_address": "198.18.0.8:443"}},
    ]
    path = _make_netlog(events)
    requests = [AttributedRequest("branch.1", "T", "F", "https://cdn.example/asset.js", "Script", 1.0)]
    try:
        connections = trace_transport(requests, path)
    finally:
        os.unlink(path)
    assert len(connections) == 1
    assert connections[0].netlog_source_id == 160
    assert connections[0].src_ip == "198.18.0.1"
    assert connections[0].dst_ip == "198.18.0.8"




def test_duplicate_transport_aliases_with_overlapping_requests_are_merged():
    events = [
        {"time": "1000", "type": 0, "phase": 0, "source": {"id": 100, "type": 1},
         "params": {"url": "https://alias.example/a.js", "source_dependency": {"id": 200, "type": 14}}},
        {"time": "1001", "type": 0, "phase": 0, "source": {"id": 101, "type": 1},
         "params": {"url": "https://alias.example/a.js", "source_dependency": {"id": 201, "type": 14}}},
        {"time": "1010", "type": 50, "phase": 2, "source": {"id": 200, "type": 14},
         "params": {"local_address": "198.18.0.1:43000", "remote_address": "198.18.0.9:443"}},
        {"time": "1011", "type": 50, "phase": 2, "source": {"id": 201, "type": 14},
         "params": {"local_address": "198.18.0.1:43000", "remote_address": "198.18.0.9:443"}},
    ]
    path = _make_netlog(events)
    requests = [AttributedRequest("alias.1", "T", "F", "https://alias.example/a.js", "Script", 1.0)]
    try:
        connections = trace_transport(requests, path)
    finally:
        os.unlink(path)
    assert len(connections) == 1
    assert connections[0].request_ids == ["alias.1"]



if __name__ == "__main__":
    test_trace_single_request()
    test_trace_unknown_cdn_matched_by_url()
    test_trace_no_match()
    test_trace_multiple_requests_same_connection()
    print("\n✓ All NetLog transport tracer tests passed!")
