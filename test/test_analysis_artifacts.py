"""Tests for persisted UI-ready normalized analysis artifacts."""

import json

from traffictracer.analyze.artifacts import (
    layered_coverage,
    persist_analysis_artifacts,
)
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
    assert summary["coverage_source"] == "core_only"
    assert summary["coverage"] == layered_coverage([], [], index["items"])
    assert summary["quality_state"] == "passed"
    assert summary["capture_global_quality_state"] == "degraded"
    assert all(
        warning["scope"] == "capture_global"
        and warning["affects_page_quality"] is False
        for warning in summary["warnings"]
    )
    assert summary["quality"]["capture_global"]["logical_flows"] == {
        "total": 3, "with_post_flow": 2, "missing_post_flow": 1,
        "errors": 1,
    }
    assert summary["quality"]["pcap_extraction"]["requested"] is False


def test_layered_coverage_conserves_each_denominator_for_partial_trace():
    requests = [
        {"attribution": {"status": "matched"}},
        {
            "network_observation": "disk_cache",
            "attribution": {
                "status": "unmatched",
                "unmatched_reason": "non_network_response",
            },
        },
        {
            "attribution": {
                "status": "ambiguous",
                "unmatched_reason": "multiple_candidates",
            }
        },
        {
            "attribution": {
                "status": "unmatched",
                "unmatched_reason": "no_transport_connection",
            }
        },
    ]
    connections = [
        {
            "match": {"status": "matched", "method": "exact_pre_flow"},
            "post_flow": {"complete": True},
            "shared": True,
        },
        {
            "match": {
                "status": "ambiguous",
                "method": "endpoint_time",
                "unmatched_reason": "multiple_candidates",
            },
            "post_flow": None,
            "shared": False,
        },
        {
            "match": {
                "status": "unmatched",
                "method": "none",
                "unmatched_reason": "no_candidate",
            },
            "post_flow": None,
            "shared": False,
        },
    ]
    core_flows = [
        {"post_flow": {"complete": True}, "shared": True},
        {"post_flow": None, "shared": False},
        {"post_flow": None, "shared": False},
        {"post_flow": {"complete": True}, "shared": False},
    ]
    coverage = layered_coverage(requests, connections, core_flows)
    for name in ("browser_requests", "transport_connections"):
        partition = coverage[name]
        accounted = (
            partition["matched"]
            + partition["ambiguous"]
            + partition["unmatched"]
        )
        if name == "browser_requests":
            accounted += partition["non_network"]
        assert accounted == partition["total"]
    assert coverage["browser_requests"]["non_network"] == 1
    assert coverage["core_logical_flows"] == {
        "total": 4,
        "with_post_flow": 2,
        "shared": 1,
        "missing_post_flow": 2,
    }
    assert coverage["unmatched_reasons"] == {
        "missing_post_flow": 2,
        "multiple_candidates": 2,
        "no_candidate": 1,
        "no_transport_connection": 1,
    }


def test_summary_is_recomputable_from_v2_indexes(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    results = tmp_path / "results"
    results.mkdir()
    requests = [
        {"attribution": {"status": "matched"}},
        {
            "attribution": {
                "status": "unmatched",
                "unmatched_reason": "no_transport_connection",
            }
        },
    ]
    connections = [
        {
            "match": {"status": "matched", "method": "exact_pre_flow"},
            "post_flow": {"complete": True},
            "shared": False,
        }
    ]
    generation = "78fdab68-4e5d-4b67-9910-33da00a2632a"
    (results / "request-index-v2.json").write_text(
        json.dumps({
            "analysis_generation_id": generation,
            "items": requests,
        }),
        encoding="utf-8",
    )
    (results / "connection-index-v2.json").write_text(
        json.dumps({
            "analysis_generation_id": generation,
            "items": connections,
        }),
        encoding="utf-8",
    )

    artifacts = persist_analysis_artifacts(tmp_path, SESSION_ID)
    summary = json.loads(artifacts.summary.read_text(encoding="utf-8"))
    flow_index = json.loads(artifacts.flow_index.read_text(encoding="utf-8"))
    assert summary["coverage"] == layered_coverage(
        requests,
        connections,
        flow_index["items"],
    )
    assert summary["coverage_source"] == "v2_indexes"
    assert summary["analysis_generation_id"] == generation
    assert summary["match_method_counts"] == {"exact_pre_flow": 1}
    assert summary["quality_state"] == "degraded"
    assert summary["quality"]["request_attribution"]["eligible"] == 2


def test_summary_reports_transport_dial_and_pcap_quality_warnings(tmp_path):
    (tmp_path / "logs").mkdir()
    results = tmp_path / "results"
    results.mkdir()
    generation = "78fdab68-4e5d-4b67-9910-33da00a2632a"
    (results / "request-index-v2.json").write_text(json.dumps({
        "analysis_generation_id": generation,
        "items": [{
            "network_observation": "network",
            "attribution": {"status": "unmatched"},
        }],
    }), encoding="utf-8")
    (results / "connection-index-v2.json").write_text(json.dumps({
        "analysis_generation_id": generation,
        "items": [{
            "connection_id": "conn-11111111111111111111111111111111",
            "match": {"status": "unmatched", "method": "none"},
            "post_flow": None,
            "terminal": {"status": "dial_error", "stage": "dial"},
            "shared": False,
        }],
    }), encoding="utf-8")
    (results / "pcap-index-v1.json").write_text(json.dumps({
        "analysis_generation_id": generation,
        "split_mode": "unique_connections",
        "connections": [{
            "connection_id": "conn-11111111111111111111111111111111",
            "pre_proxy": {"status": "empty"},
            "post_proxy": {"status": "not_requested"},
        }],
    }), encoding="utf-8")

    summary = json.loads(
        persist_analysis_artifacts(tmp_path, SESSION_ID).summary.read_text(
            encoding="utf-8",
        )
    )
    codes = [warning["code"] for warning in summary["warnings"]]
    assert codes == [
        "REQUEST_ATTRIBUTION_UNMATCHED",
        "TRANSPORT_UNMATCHED",
        "EGRESS_DIAL_FAILED",
        "PCAP_PRE_EMPTY",
        "PCAP_POST_UNAVAILABLE",
    ]
    assert summary["quality_state"] == "degraded"
    assert summary["capture_global_quality_state"] == "passed"
    assert all(
        warning["scope"] == "page_attributed"
        and warning["affects_page_quality"] is True
        for warning in summary["warnings"]
    )
    assert summary["quality"]["egress_establishment"] == {
        "total": 1, "established": 0, "failed_before_socket": 1,
        "unavailable": 0,
    }


def test_local_endpoint_is_informational_and_post_pcap_is_not_applicable(tmp_path):
    (tmp_path / "logs").mkdir()
    results = tmp_path / "results"
    results.mkdir()
    generation = "78fdab68-4e5d-4b67-9910-33da00a2632a"
    connection_id = "conn-11111111111111111111111111111111"
    url = "https://localhost.weixin.qq.com:14017/wx_game_base/api/business"
    pre_flow = {
        "network": "tcp", "src_ip": "198.18.0.1", "src_port": 44000,
        "dst_ip": "198.18.0.226", "dst_port": 14017,
    }
    (results / "request-index-v2.json").write_text(json.dumps({
        "analysis_generation_id": generation,
        "items": [{
            "request_id": "local.1", "url": url,
            "connection_id": connection_id,
            "network_observation": "local_endpoint",
            "attribution": {"status": "matched"},
        }],
    }), encoding="utf-8")
    (results / "connection-index-v2.json").write_text(json.dumps({
        "analysis_generation_id": generation,
        "items": [{
            "connection_id": connection_id,
            "request_ids": ["local.1"], "urls": [url], "primary_url": url,
            "pre_flow": pre_flow, "post_flow": None,
            "match": {"status": "matched", "method": "exact_pre_flow"},
            "terminal": {"status": "dial_error", "stage": "dial"},
            "shared": False,
        }],
    }), encoding="utf-8")
    (results / "pcap-index-v1.json").write_text(json.dumps({
        "analysis_generation_id": generation,
        "split_mode": "unique_connections",
        "connections": [{
            "connection_id": connection_id, "request_ids": ["local.1"],
            "pre_proxy": {"status": "success"},
            "post_proxy": {"status": "not_requested"},
        }],
    }), encoding="utf-8")

    summary = json.loads(
        persist_analysis_artifacts(tmp_path, SESSION_ID).summary.read_text(
            encoding="utf-8",
        )
    )

    assert summary["quality_state"] == "passed"
    assert [item["code"] for item in summary["warnings"]] == [
        "LOCAL_ENDPOINT_UNAVAILABLE", "PCAP_POST_NOT_APPLICABLE",
    ]
    assert all(item["severity"] == "info" for item in summary["warnings"])
    assert summary["quality"]["request_attribution"] == {
        "eligible": 0, "matched": 0, "ambiguous": 0, "unmatched": 0,
    }
    assert summary["quality"]["egress_establishment"] == {
        "total": 1, "established": 0, "failed_before_socket": 0,
        "unavailable": 0, "not_applicable_local_endpoint": 1,
    }
    assert summary["quality"]["pcap_extraction"] == {
        "requested": True, "total": 1, "applicable": 0,
        "pre_success": 1, "post_success": 0, "complete_pairs": 0,
        "post_not_applicable": 1,
    }
    assert summary["coverage"]["page_attributed"]["unmatched_reasons"] == {
        "local_endpoint_not_applicable": 1,
    }


def test_empty_layered_coverage_has_three_zero_denominators():
    coverage = layered_coverage([], [])
    assert coverage["browser_requests"]["total"] == 0
    assert coverage["browser_requests"]["non_network"] == 0
    assert coverage["transport_connections"]["total"] == 0
    assert coverage["core_logical_flows"] == {
        "total": 0,
        "with_post_flow": 0,
        "shared": 0,
        "missing_post_flow": 0,
    }


def test_flow_index_backfills_requests_urls_and_generation_from_v2(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    pre = _flow("tcp", "198.18.0.1", 41000, "198.18.0.12", 443, "logical")
    post = _flow("tcp", "192.0.2.10", 51000, "203.0.113.8", 24191, "physical")
    (raw / "mihomo-trace.jsonl").write_text(
        "\n".join([
            json.dumps({
                "type": "tcp_connect",
                "conn_id": "mihomo-1",
                "pre_flow": pre,
            }),
            json.dumps({
                "type": "tcp_proxy_dial",
                "conn_id": "mihomo-1",
                "outer_conn_id": "outer-1",
                "post_flow": post,
            }),
        ]) + "\n",
        encoding="utf-8",
    )
    results = tmp_path / "results"
    results.mkdir()
    generation = "78fdab68-4e5d-4b67-9910-33da00a2632a"
    connection_id = "conn-11111111111111111111111111111111"
    url_one = "https://www.youtube.com/"
    url_two = "https://www.youtube.com/app.js"
    (results / "request-index-v2.json").write_text(json.dumps({
        "analysis_generation_id": generation,
        "items": [
            {
                "request_id": "1.1",
                "url": url_one,
                "connection_id": connection_id,
                "network_observation": "network",
                "attribution": {"status": "matched"},
            },
            {
                "request_id": "1.2",
                "url": url_two,
                "connection_id": connection_id,
                "network_observation": "network",
                "attribution": {"status": "matched"},
            },
        ],
    }), encoding="utf-8")
    (results / "connection-index-v2.json").write_text(json.dumps({
        "analysis_generation_id": generation,
        "items": [{
            "connection_id": connection_id,
            "mihomo_connection_id": "mihomo-1",
            "request_ids": ["1.1", "1.2"],
            "urls": [url_one, url_two],
            "primary_url": url_one,
            "post_flow": {"complete": True},
            "shared": True,
            "match": {"status": "matched", "method": "exact_pre_flow"},
        }],
    }), encoding="utf-8")

    artifacts = persist_analysis_artifacts(tmp_path, SESSION_ID)
    index = json.loads(artifacts.flow_index.read_text(encoding="utf-8"))
    summary = json.loads(artifacts.summary.read_text(encoding="utf-8"))
    flow = index["items"][0]

    assert index["analysis_generation_id"] == generation
    assert flow["conn_id"] == "mihomo-1"
    assert flow["request_ids"] == ["1.1", "1.2"]
    assert flow["connection_ids"] == [connection_id]
    assert flow["primary_url"] == url_one
    assert flow["url"] == url_one
    assert flow["urls"] == [url_one, url_two]
    assert summary["consistency"]["status"] == "passed"
