import json

from traffictracer.analyze.flow_index import FlowIndex


def _flow(scope: str) -> dict:
    return {
        "network": "tcp",
        "src_ip": "198.18.0.1" if scope == "logical" else "192.0.2.1",
        "src_port": 40000 if scope == "logical" else 50000,
        "dst_ip": "1.1.1.1" if scope == "logical" else "203.0.113.1",
        "dst_port": 443,
        "key": f"tcp|{scope}",
        "complete": True,
        "scope": scope,
        "source": "test",
        "shared": False,
    }


def test_connection_bound_semantics_reference_reaches_flow_index(tmp_path):
    events = [
        {"type": "tcp_connect", "conn_id": "t1", "pre_flow": _flow("logical")},
        {
            "type": "tcp_proxy_dial",
            "conn_id": "t1",
            "outer_conn_id": "o1",
            "snapshot_id": "sha256:" + "a" * 64,
            "config_generation": 9,
            "adapter_instance_id": "adapter-0123456789abcdef-000001",
            "adapter_protocol": "vless",
            "behavior_fingerprint": "sha256:" + "b" * 64,
            "post_flow": _flow("physical"),
        },
    ]
    trace = tmp_path / "trace.jsonl"
    trace.write_text("\n".join(json.dumps(event) for event in events))

    mapping = FlowIndex.from_log(str(trace)).mappings[0]
    assert mapping.proxy_semantics is not None
    assert mapping.proxy_semantics.snapshot_id == "sha256:" + "a" * 64
    assert mapping.proxy_semantics.config_generation == 9
    assert mapping.proxy_semantics.adapter_instance_id.endswith("-000001")
    assert mapping.proxy_semantics.protocol == "vless"


def test_partial_semantics_reference_is_not_treated_as_authoritative(tmp_path):
    events = [
        {"type": "tcp_connect", "conn_id": "t1", "pre_flow": _flow("logical")},
        {
            "type": "tcp_proxy_dial",
            "conn_id": "t1",
            "snapshot_id": "sha256:" + "a" * 64,
            "config_generation": 9,
            "adapter_protocol": "vless",
            "post_flow": _flow("physical"),
        },
    ]
    trace = tmp_path / "trace.jsonl"
    trace.write_text("\n".join(json.dumps(event) for event in events))

    assert FlowIndex.from_log(str(trace)).mappings[0].proxy_semantics is None
