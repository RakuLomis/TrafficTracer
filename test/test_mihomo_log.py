"""Tests for Mihomo tracing log parser."""

import sys
import json
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.analyze.mihomo_log import (
    parse_tracing_log, MihomoConnection, TcpConnect, TcpProxyDial, TcpClose,
)


def test_parse_tracing_log():
    content = """\
{"ts":"2025-07-05T10:00:00Z","type":"tcp_connect","conn_id":"conn-1","src":"127.0.0.1:55555","dst":"127.0.0.1:7890","host":"www.example.com"}
{"ts":"2025-07-05T10:00:01Z","type":"tcp_proxy_dial","conn_id":"conn-1","proxy":"Proxy","proxy_type":"ss","proxy_addr":"1.2.3.4:443","out_src":"192.168.1.100:41234"}
{"ts":"2025-07-05T10:00:10Z","type":"tcp_close","conn_id":"conn-1","bytes_up":1024,"bytes_down":4096,"duration_ms":9000}
{"ts":"2025-07-05T10:00:00Z","type":"tcp_connect","conn_id":"conn-2","src":"127.0.0.1:55556","dst":"127.0.0.1:7890","host":"cdn.example.com"}
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write(content)
        tmp = f.name

    try:
        conns = parse_tracing_log(tmp)
        assert len(conns) == 2
        assert "conn-1" in conns
        c1 = conns["conn-1"]
        assert c1.connect is not None
        assert c1.connect.src == "127.0.0.1:55555"
        assert c1.connect.host == "www.example.com"
        assert c1.proxy_dial is not None
        assert c1.proxy_dial.out_src == "192.168.1.100:41234"
        assert c1.close is not None
        assert c1.close.bytes_up == 1024
        assert c1.close.bytes_down == 4096

        c2 = conns["conn-2"]
        assert c2.connect is not None
        assert c2.proxy_dial is None
        assert c2.close is None
    finally:
        os.unlink(tmp)

    print("  ✓ Mihomo log parsing pass")


def test_parse_empty_log():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write("\n")
        tmp = f.name
    try:
        conns = parse_tracing_log(tmp)
        assert len(conns) == 0
    finally:
        os.unlink(tmp)


if __name__ == "__main__":
    test_parse_tracing_log()
    test_parse_empty_log()
    print("\n✓ All Mihomo log parser tests passed!")


def test_parse_normalized_udp_proxy_dial(tmp_path):
    import json
    from traffictracer.analyze.mihomo_log import parse_udp_tracing_log
    events = [
        {"type": "udp_connect", "conn_key": "u1", "event_seq": 1,
         "pre_flow": {"network": "udp", "src_ip": "198.18.0.1", "src_port": 50000,
                      "dst_ip": "1.1.1.1", "dst_port": 443,
                      "key": "udp|198.18.0.1:50000|1.1.1.1:443", "complete": True}},
        {"type": "udp_proxy_dial", "conn_key": "u1", "outer_conn_id": "outer-u1",
         "proxy": "automatic", "proxy_type": "URLTest",
         "leaf_proxy": "tuic-node", "leaf_proxy_type": "Tuic",
         "egress_outcome": "proxy",
         "post_flow": {"network": "udp", "src_ip": "192.0.2.1", "src_port": 51000,
                       "dst_ip": "203.0.113.1", "dst_port": 443,
                       "key": "udp|192.0.2.1:51000|203.0.113.1:443", "complete": True}},
    ]
    path = tmp_path / "udp.jsonl"
    path.write_text("\n".join(json.dumps(event) for event in events))
    conn = parse_udp_tracing_log(str(path))["u1"]
    assert conn.connect.pre_flow.key == "udp|198.18.0.1:50000|1.1.1.1:443"
    assert conn.proxy_dial.post_flow.dst == "203.0.113.1:443"
    assert conn.proxy_dial.outer_conn_id == "outer-u1"
    assert conn.proxy_dial.leaf_proxy == "tuic-node"
    assert conn.proxy_dial.leaf_proxy_type == "Tuic"
    assert conn.proxy_dial.egress_outcome == "proxy"


def test_trace_barrier_cutoff_excludes_late_events(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    trace = raw / "mihomo-trace.jsonl"
    events = [
        {"type": "tcp_connect", "conn_id": "c1", "event_seq": 1, "src": "198.18.0.1:40000", "dst": "1.1.1.1:443"},
        {"type": "tcp_proxy_dial", "conn_id": "c1", "event_seq": 2, "egress_outcome": "direct"},
        {"type": "trace_barrier", "session_id": "s1", "event_seq": 3},
        {"type": "tcp_close", "conn_id": "c1", "event_seq": 4, "status": "closed"},
    ]
    trace.write_text("\n".join(json.dumps(event) for event in events), encoding="utf-8")
    (raw / "capture-context.json").write_text(json.dumps({
        "trace_boundary": {
            "source": "mihomo_barrier", "session_id": "s1",
            "event_seq": 3, "ts": "2026-08-12T00:00:00Z", "output": str(trace),
        }
    }), encoding="utf-8")

    from traffictracer.analyze.mihomo_log import trace_snapshot_info
    bounded = parse_tracing_log(str(trace), max_event_seq=3)["c1"]
    assert bounded.connect is not None
    assert bounded.proxy_dial is not None
    assert bounded.close is None
    assert parse_tracing_log(str(trace))["c1"].close is not None
    snapshot = trace_snapshot_info(str(trace))
    assert snapshot["source"] == "mihomo_barrier"
    assert snapshot["cutoff_event_seq"] == 3
    assert snapshot["late_event_count"] == 1
    assert snapshot["max_observed_event_seq"] == 4
    assert snapshot["barrier_verified"] is True


def test_trace_barrier_cutoff_rejects_missing_marker(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    trace = raw / "mihomo-trace.jsonl"
    trace.write_text(json.dumps({
        "type": "tcp_connect", "conn_id": "c1", "event_seq": 1
    }), encoding="utf-8")
    (raw / "capture-context.json").write_text(json.dumps({
        "trace_boundary": {
            "source": "mihomo_barrier", "session_id": "s1",
            "event_seq": 2, "ts": "2026-08-12T00:00:00Z", "output": str(trace),
        }
    }), encoding="utf-8")
    from traffictracer.analyze.mihomo_log import trace_snapshot_info
    import pytest
    with pytest.raises(ValueError, match="barrier marker"):
        trace_snapshot_info(str(trace))
