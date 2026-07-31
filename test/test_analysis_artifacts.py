"""Tests for persisted UI-ready normalized analysis artifacts."""

import json

from traffictracer.analyze.artifacts import persist_analysis_artifacts
from traffictracer.contracts import validate_flow


SESSION_ID = "5027aee9-c6e4-41de-8625-7ea0869a3307"


def _flow(network, src_ip, src_port, dst_ip, dst_port, scope, shared=False):
    src = f"[{src_ip}]:{src_port}" if ":" in src_ip else f"{src_ip}:{src_port}"
    dst = f"[{dst_ip}]:{dst_port}" if ":" in dst_ip else f"{dst_ip}:{dst_port}"
    return {
        "network": network,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "key": f"{network}|{src}|{dst}",
        "complete": True,
        "scope": scope,
        "source": "mihomo",
        "shared": shared,
    }


def test_flow_index_and_summary_keep_duplicates_shared_and_null_post(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    pre_reused = _flow("tcp", "198.18.0.1", 40000, "1.1.1.1", 443, "logical")
    pre_other = _flow("tcp", "198.18.0.1", 40001, "1.0.0.1", 443, "logical")
    post_one = _flow("tcp", "192.0.2.1", 50000, "203.0.113.1", 443, "physical")
    post_two = _flow("tcp", "192.0.2.1", 50000, "203.0.113.2", 443, "physical")
    events = [
        {"type": "tcp_connect", "conn_id": "t1", "pre_flow": pre_reused},
        {
            "type": "tcp_proxy_dial",
            "conn_id": "t1",
            "outer_conn_id": "shared-outer",
            "post_flow": post_one,
        },
        {"type": "tcp_connect", "conn_id": "t2", "pre_flow": pre_reused},
        {
            "type": "tcp_close",
            "conn_id": "t2",
            "status": "error",
            "error": "dial failed",
        },
        {"type": "tcp_connect", "conn_id": "t3", "pre_flow": pre_other},
        {
            "type": "tcp_proxy_dial",
            "conn_id": "t3",
            "outer_conn_id": "shared-outer",
            "post_flow": post_two,
        },
    ]
    trace = logs / "mihomo_trace_example.com_all_1.jsonl"
    trace.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    artifacts = persist_analysis_artifacts(tmp_path, SESSION_ID)
    index = json.loads(artifacts.flow_index.read_text(encoding="utf-8"))
    summary = json.loads(artifacts.summary.read_text(encoding="utf-8"))
    assert index["pagination"] == {
        "total": 3,
        "default_limit": 100,
        "max_limit": 1000,
    }
    assert [item["conn_id"] for item in index["items"]] == ["t1", "t2", "t3"]
    assert all(validate_flow(item) is item for item in index["items"])
    by_id = {item["conn_id"]: item for item in index["items"]}
    assert by_id["t1"]["match"]["status"] == "ambiguous"
    assert by_id["t1"]["match"]["candidate_count"] == 2
    assert by_id["t2"]["post_flow"] is None
    assert by_id["t2"]["match"]["status"] == "unmatched"
    assert by_id["t1"]["shared"] is True
    assert by_id["t3"]["shared"] is True
    assert summary["total_flows"] == 3
    assert summary["shared_flows"] == 2
    assert summary["missing_post_flows"] == 1
    assert summary["duplicate_pre_flow_keys"] == 1
    assert summary["error_flows"] == 1
    assert [warning["code"] for warning in summary["warnings"]] == [
        "DUPLICATE_PRE_FLOW",
        "SHARED_OUTER_FLOW",
        "POST_FLOW_UNAVAILABLE",
        "FLOW_ERRORS",
    ]
