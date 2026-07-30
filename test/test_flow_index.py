import json

from traffictracer.analyze.flow_index import FlowIndex, flow_key


def _flow(network, src_ip, src_port, dst_ip, dst_port, scope):
    src = f"[{src_ip}]:{src_port}" if ":" in src_ip else f"{src_ip}:{src_port}"
    dst = f"[{dst_ip}]:{dst_port}" if ":" in dst_ip else f"{dst_ip}:{dst_port}"
    return {"network": network, "src_ip": src_ip, "src_port": src_port,
            "dst_ip": dst_ip, "dst_port": dst_port, "key": f"{network}|{src}|{dst}",
            "complete": True, "scope": scope, "source": "test", "shared": False}


def test_exact_tcp_and_udp_lookup(tmp_path):
    events = [
        {"type": "tcp_connect", "conn_id": "t1", "pre_flow": _flow("tcp", "198.18.0.1", 40000, "1.1.1.1", 443, "logical")},
        {"type": "tcp_proxy_dial", "conn_id": "t1", "outer_conn_id": "o1", "post_flow": _flow("tcp", "192.0.2.1", 50000, "203.0.113.1", 443, "physical")},
        {"type": "udp_connect", "conn_key": "u1", "pre_flow": _flow("udp", "2001:db8::1", 53000, "2001:db8::2", 443, "logical")},
        {"type": "udp_proxy_dial", "conn_key": "u1", "outer_conn_id": "o2", "post_flow": _flow("udp", "192.0.2.1", 51000, "203.0.113.2", 443, "physical")},
    ]
    path = tmp_path / "trace.jsonl"
    path.write_text("\n".join(json.dumps(event) for event in events))
    index = FlowIndex.from_log(str(path))
    tcp = index.lookup("tcp", "198.18.0.1", 40000, "1.1.1.1", 443)
    udp = index.lookup_key(flow_key("udp6", "2001:db8::1", 53000, "2001:db8::2", 443))
    assert tcp[0].post_flow.dst_ip == "203.0.113.1"
    assert tcp[0].outer_conn_id == "o1"
    assert udp[0].post_flow.src_port == 51000
