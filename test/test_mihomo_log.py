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
{"ts":"2025-07-05T10:00:10Z","type":"tcp_close","conn_id":"conn-1","bytes_up":1024,"bytes_down":4096,"duration_ms":9000,"status":"dial_error","stage":"dial","error_class":"connection_refused","error":"opaque"}
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
        assert c1.close.error_class == "connection_refused"
        assert c1.close.error_class_source == "core_explicit"

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
         "carrier_id": "hy2-carrier-1", "carrier_relation": "reused",
         "carrier_generation": 3, "carrier_protocol": "hysteria2",
         "carrier_paths": [{"network": "udp", "src_ip": "192.0.2.1",
                            "src_port": 51000, "dst_ip": "203.0.113.1",
                            "dst_port": 443, "capture_scope": "physical",
                            "shared": True}],
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

    assert conn.proxy_dial.carrier_id == "hy2-carrier-1"
    assert conn.proxy_dial.carrier_relation == "reused"
    assert conn.proxy_dial.carrier_generation == 3
    assert conn.proxy_dial.carrier_protocol == "hysteria2"
    assert conn.proxy_dial.carrier_paths[0].shared is True

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
    assert snapshot["late_event_types"] == {"tcp_close": 1}
    assert snapshot["max_late_delay_ms"] == 0.0
    assert snapshot["max_observed_event_seq"] == 4
    assert snapshot["barrier_verified"] is True


def test_trace_snapshot_includes_only_causal_same_session_tail(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    trace = raw / "mihomo-trace.jsonl"
    events = [
        {
            "type": "tcp_connect", "session_id": "s1", "conn_id": "c1",
            "event_seq": 1, "src": "198.18.0.1:40000",
            "dst": "1.1.1.1:443",
        },
        {"type": "trace_barrier", "session_id": "s1", "event_seq": 2},
        {
            "type": "tcp_proxy_dial", "session_id": "s1", "conn_id": "c1",
            "event_seq": 3, "ts": "2026-08-12T00:00:00.340Z",
            "egress_outcome": "direct",
            "post_flow": {
                "network": "tcp", "src_ip": "192.0.2.1", "src_port": 50000,
                "dst_ip": "1.1.1.1", "dst_port": 443, "complete": True,
            },
        },
        {
            "type": "tcp_close", "session_id": "other", "conn_id": "c1",
            "event_seq": 4, "ts": "2026-08-12T00:00:00.500Z",
            "status": "closed",
        },
        {
            "type": "tcp_connect", "session_id": "s1", "conn_id": "late",
            "event_seq": 5, "ts": "2026-08-12T00:00:00.600Z",
        },
        {
            "type": "tcp_proxy_dial", "session_id": "s1", "conn_id": "late",
            "event_seq": 6, "ts": "2026-08-12T00:00:00.700Z",
            "egress_outcome": "direct",
        },
        {
            "type": "tcp_close", "session_id": "s1", "conn_id": "c1",
            "event_seq": 7, "ts": "2026-08-12T00:00:03.000Z",
            "status": "closed",
        },
    ]
    trace.write_text("\n".join(json.dumps(event) for event in events), encoding="utf-8")
    (raw / "capture-context.json").write_text(json.dumps({
        "trace_boundary": {
            "source": "mihomo_barrier", "session_id": "s1",
            "event_seq": 2, "ts": "2026-08-12T00:00:00Z", "output": str(trace),
        }
    }), encoding="utf-8")

    from traffictracer.analyze.mihomo_log import trace_snapshot_info
    snapshot = trace_snapshot_info(str(trace))
    assert snapshot["causal_tail_event_seqs"] == [3]
    assert snapshot["causal_tail_event_count"] == 1
    assert snapshot["causal_tail_event_types"] == {"tcp_proxy_dial": 1}
    bounded = parse_tracing_log(
        str(trace), snapshot["cutoff_event_seq"],
        set(snapshot["causal_tail_event_seqs"]),
    )
    assert bounded["c1"].proxy_dial is not None
    assert bounded["c1"].close is None
    assert "late" not in bounded


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


def test_observed_proxy_protocols_respects_cutoff_and_ignores_direct(tmp_path):
    from traffictracer.analyze.mihomo_log import observed_proxy_protocols
    events = [
        {"type": "udp_proxy_dial", "event_seq": 1,
         "egress_outcome": "proxy", "carrier_protocol": "Hysteria2"},
        {"type": "tcp_proxy_dial", "event_seq": 2,
         "egress_outcome": "direct", "leaf_proxy_type": "Direct"},
        {"type": "tcp_proxy_dial", "event_seq": 3,
         "egress_outcome": "proxy", "leaf_proxy_type": "Vless"},
    ]
    path = tmp_path / "trace.jsonl"
    path.write_text("\n".join(json.dumps(event) for event in events))

    observation = observed_proxy_protocols(str(path), max_event_seq=2)

    assert observation["protocols"] == ["hysteria2"]
    assert observation["proxy_dial_events"] == 1
    assert observation["unknown_protocol_events"] == 0


def test_parse_carrier_lifecycle_and_binding_events(tmp_path):
    from traffictracer.analyze.mihomo_log import (
        build_carrier_path_registry,
        parse_carrier_events,
    )
    path_value = {
        "network": "udp", "src_ip": "192.0.2.10", "src_port": 55000,
        "dst_ip": "203.0.113.20", "dst_port": 443,
        "complete": True, "scope": "physical", "shared": True,
    }
    events = [
        {"type": "carrier_open", "event_seq": 1,
         "carrier_id": "carrier-1", "carrier_generation": 1,
         "carrier_protocol": "hysteria2", "post_flow": path_value,
         "carrier_paths": [path_value]},
        {"type": "logical_carrier_bind", "event_seq": 2,
         "carrier_id": "carrier-1", "carrier_relation": "reused",
         "logical_conn_id": "tcp-1", "conn_id": "tcp-1",
         "carrier_generation": 1, "carrier_protocol": "hysteria2",
         "carrier_paths": [path_value]},
        {"type": "carrier_close", "event_seq": 3,
         "carrier_id": "carrier-1"},
    ]
    path = tmp_path / "carrier.jsonl"
    path.write_text("\n".join(json.dumps(event) for event in events))

    records = parse_carrier_events(str(path), max_event_seq=2)

    assert [record.event_type for record in records] == [
        "carrier_open", "logical_carrier_bind",
    ]
    assert records[1].logical_conn_id == "tcp-1"
    assert records[1].physical_paths[0].shared is True

    registry = build_carrier_path_registry(records)
    assert list(registry) == [("carrier-1", 1)]
    assert registry[("carrier-1", 1)] == (records[0].physical_paths[0],)


def test_carrier_registry_merges_late_path_update(tmp_path):
    from traffictracer.analyze.mihomo_log import (
        build_carrier_path_registry,
        parse_carrier_events,
    )
    first = {
        "network": "udp", "src_ip": "192.0.2.10", "src_port": 55000,
        "dst_ip": "203.0.113.20", "dst_port": 443,
        "complete": True, "scope": "physical", "shared": True,
    }
    second = dict(first, dst_ip="203.0.113.21", dst_port=8443)
    path = tmp_path / "carrier-update.jsonl"
    path.write_text("\n".join(json.dumps(event) for event in [
        {"type": "carrier_open", "event_seq": 1,
         "carrier_id": "carrier-1", "carrier_generation": 7,
         "carrier_protocol": "hysteria2", "carrier_paths": [first]},
        {"type": "logical_carrier_bind", "event_seq": 2,
         "carrier_id": "carrier-1", "carrier_generation": 7,
         "logical_conn_id": "tcp-1", "carrier_paths": [first]},
        {"type": "carrier_path_update", "event_seq": 3,
         "carrier_id": "carrier-1", "carrier_generation": 7,
         "carrier_protocol": "hysteria2", "carrier_paths": [first, second]},
    ]))

    registry = build_carrier_path_registry(parse_carrier_events(str(path)))

    assert [item.dst_ip for item in registry[("carrier-1", 7)]] == [
        "203.0.113.20", "203.0.113.21",
    ]

    from types import SimpleNamespace
    from traffictracer.models import CarrierBinding
    flow = SimpleNamespace(
        carrier_binding=CarrierBinding(
            carrier_id="carrier-1", relation="reused", generation=7,
            protocol="hysteria2", paths=(registry[("carrier-1", 7)][0],),
        ),
        match_evidence=[],
    )
    from traffictracer.analyze.mihomo_log import enrich_carrier_bindings
    assert enrich_carrier_bindings([flow], registry) == 1
    assert len(flow.carrier_binding.paths) == 2
    assert flow.match_evidence == ["carrier_paths_enriched_from_lifecycle"]


def test_legacy_binding_recovers_protocol_and_path_from_explicit_evidence(tmp_path):
    from traffictracer.analyze.mihomo_log import parse_carrier_events
    post_flow = {
        "network": "tcp", "src_ip": "192.0.2.10", "src_port": 55000,
        "dst_ip": "203.0.113.20", "dst_port": 443, "complete": True,
        "scope": "physical", "source": "dialer_socket", "shared": True,
    }
    path = tmp_path / "legacy-carrier.jsonl"
    path.write_text(json.dumps({
        "type": "logical_carrier_bind", "event_seq": 1,
        "carrier_id": "carrier-legacy", "logical_conn_id": "tcp-1",
        "leaf_proxy_type": "Hysteria2", "post_flow": post_flow,
    }) + "\n")

    record = parse_carrier_events(str(path))[0]
    assert record.protocol == "hysteria2"
    assert len(record.physical_paths) == 1
    assert record.physical_paths[0].src_ip == "192.0.2.10"
    assert record.physical_paths[0].dst_ip == "203.0.113.20"
