"""Tests for persisted UI-ready normalized analysis artifacts."""

import json
from collections import Counter

from traffictracer.analyze.artifacts import (
    _browser_request_failure_summary,
    _carrier_binding_summary,
    _capture_inbound_summary,
    _capture_protocol_summary,
    _local_connection_ids,
    _analysis_integrity_state,
    _mapping_error_class,
    _mapping_targets_loopback,
    _quality_warnings,
    _warnings,
    analysis_quality,
    _target_document_non_network,
    layered_coverage,
    persist_analysis_artifacts,
)
from traffictracer.contracts import validate_flow
from traffictracer.analyze.flow_index import FlowMapping
from traffictracer.models import FlowTuple


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
    assert by_id["t1"]["match"]["status"] == "matched"
    assert "native connection identity" in by_id["t1"]["match"]["reason"]
    assert by_id["t1"]["match"]["candidate_count"] == 2
    assert by_id["t2"]["post_flow"] is None
    assert by_id["t2"]["match"]["status"] == "unmatched"
    assert by_id["t1"]["shared"] is True
    assert by_id["t3"]["shared"] is True
    assert summary["total_flows"] == 3
    assert summary["shared_flows"] == 2
    assert summary["missing_post_flows"] == 0
    assert summary["duplicate_pre_flow_keys"] == 1
    assert summary["error_flows"] == 1
    assert [warning["code"] for warning in summary["warnings"]] == [
        "DUPLICATE_PRE_FLOW",
        "SHARED_OUTER_FLOW",
        "EGRESS_FAILED_BEFORE_SOCKET",
        "FLOW_ERRORS",
    ]
    assert summary["coverage_source"] == "core_only"
    assert summary["coverage"] == layered_coverage([], [], index["items"])
    assert summary["quality_state"] == "passed"
    assert summary["capture_global_quality_state"] == "passed"
    assert all(
        warning["scope"] == "capture_global"
        and warning["affects_page_quality"] is False
        for warning in summary["warnings"]
    )
    assert summary["quality"]["capture_global"]["logical_flows"] == {
        "total": 3, "with_post_flow": 2, "shared": 2,
        "missing_post_flow": 0, "explicit_no_socket": 0,
        "failed_before_socket": 1, "local_not_applicable": 0,
        "unexpected_missing": 0, "errors": 1,
    }
    assert summary["analysis_integrity"]["capture_global"]["state"] == "passed"
    assert summary["network_outcome"]["capture_global"]["state"] == "partial_failure"
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
        "explicit_no_socket": 0,
        "failed_before_socket": 0,
        "local_not_applicable": 0,
        "unexpected_missing": 2,
    }
    assert coverage["unmatched_reasons"] == {
        "missing_post_flow": 2,
        "multiple_candidates": 2,
        "no_candidate": 1,
        "no_transport_connection": 1,
    }


def test_unattributed_capture_tail_is_informational_not_correlation_loss():
    items = [{
        "shared": False,
        "post_flow_disposition": "unexpected_missing",
        "attribution_scope": "capture_unattributed",
        "request_ids": [],
        "terminal": None,
    }]
    warnings = _warnings(items, Counter(), set(), set())
    assert [warning["code"] for warning in warnings] == [
        "CAPTURE_TAIL_UNATTRIBUTED",
    ]
    assert warnings[0]["severity"] == "info"


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
        "EGRESS_FAILED_BEFORE_SOCKET",
        "PCAP_PRE_EMPTY",
        "PCAP_POST_NOT_REQUESTED",
    ]
    assert summary["quality_state"] == "degraded"
    assert summary["capture_global_quality_state"] == "passed"
    assert all(
        warning["scope"] == "page_attributed"
        for warning in summary["warnings"]
    )
    network_warning = next(
        warning for warning in summary["warnings"]
        if warning["code"] == "EGRESS_FAILED_BEFORE_SOCKET"
    )
    assert network_warning["severity"] == "info"
    assert network_warning["affects_page_quality"] is False
    assert summary["analysis_integrity"]["page_attributed"]["state"] == "degraded"
    assert summary["network_outcome"]["page_attributed"]["state"] == "failed"
    assert summary["quality"]["egress_establishment"] == {
        "total": 1, "established": 0, "failed_before_socket": 1,
        "unavailable": 0,
    }


def test_browser_request_failures_distinguish_later_same_url_recovery():
    records = [
        {
            "url": "https://cdn.example/app.js#first",
            "relation": "third_party",
            "failure": {
                "failed": True, "canceled": False,
                "reason": "net::ERR_CERT_VERIFIER_CHANGED",
            },
        },
        {
            "url": "https://api.example/data",
            "relation": "same_site",
            "failure": {
                "failed": True, "canceled": True,
                "reason": "net::ERR_ABORTED",
            },
        },
        {
            "url": "https://cdn.example/app.js",
            "relation": "third_party",
            "failure": {"failed": False, "canceled": False, "reason": None},
        },
    ]

    assert _browser_request_failure_summary(records) == {
        "total_requests": 3,
        "failed_occurrences": 2,
        "canceled_occurrences": 1,
        "recovered_occurrences": 1,
        "unrecovered_occurrences": 1,
        "by_reason": {
            "net::ERR_ABORTED": 1,
            "net::ERR_CERT_VERIFIER_CHANGED": 1,
        },
        "by_relation": {"same_site": 1, "third_party": 1},
        "recovered_by_reason": {"net::ERR_CERT_VERIFIER_CHANGED": 1},
        "recovery_evidence": "later_successful_occurrence_same_url",
    }


def test_browser_request_failure_does_not_claim_prior_success_as_recovery():
    records = [
        {
            "url": "https://cdn.example/app.js",
            "failure": {"failed": False},
        },
        {
            "url": "https://cdn.example/app.js",
            "failure": {"failed": True, "reason": "net::ERR_FAILED"},
        },
    ]

    summary = _browser_request_failure_summary(records)
    assert summary["recovered_occurrences"] == 0
    assert summary["unrecovered_occurrences"] == 1


def test_observed_network_failure_does_not_degrade_analysis_integrity():
    connection = {
        "connection_id": "conn-11111111111111111111111111111111",
        "match": {"status": "matched", "method": "exact_pre_flow"},
        "post_flow": None,
        "terminal": {
            "status": "resolve_error", "stage": "resolve",
            "error_class": "dns_resolution",
        },
    }
    warnings = _quality_warnings(
        [], [connection], {"split_mode": "none", "connections": []},
    )
    assert [(item["code"], item["severity"]) for item in warnings] == [
        ("EGRESS_FAILED_BEFORE_SOCKET", "info"),
    ]
    assert _analysis_integrity_state(
        {"status": "passed"}, warnings, scope="page_attributed",
    ) == "passed"


def test_rejected_egress_is_not_missing_socket_quality_failure():
    connection = {
        "connection_id": "conn-11111111111111111111111111111111",
        "match": {"status": "matched", "method": "exact_pre_flow"},
        "post_flow": None,
        "terminal": {"status": "rejected", "stage": "reject"},
        "egress": {
            "mode": "unknown", "outcome": "rejected",
            "policy": "Taobao", "selection_chain": ["Taobao", "REJECT"],
            "selected_node": "REJECT", "selected_type": "Reject",
            "evidence": "mihomo_trace",
        },
    }

    quality = analysis_quality(
        [], [connection], {"split_mode": "none", "connections": []},
    )
    assert quality["egress_establishment"] == {
        "total": 1,
        "established": 0,
        "failed_before_socket": 0,
        "unavailable": 0,
        "not_applicable_outcome": 1,
    }
    warning_codes = {
        item["code"] for item in _quality_warnings(
            [], [connection], {"split_mode": "none", "connections": []},
        )
    }
    assert "EGRESS_DIAL_FAILED" not in warning_codes
    assert "EGRESS_UNAVAILABLE" not in warning_codes


def test_rejected_egress_post_pcap_is_informational_not_missing():
    connection = {
        "connection_id": "conn-11111111111111111111111111111111",
        "match": {"status": "matched", "method": "exact_pre_flow"},
        "post_flow": None,
        "terminal": {"status": "rejected", "stage": "reject"},
        "egress": {"outcome": "rejected"},
    }
    pcap = {
        "split_mode": "unique_connections",
        "connections": [{
            "connection_id": connection["connection_id"],
            "pre_proxy": {"status": "success"},
            "post_proxy": {"status": "not_applicable"},
        }],
    }

    quality = analysis_quality([], [connection], pcap)
    assert quality["pcap_extraction"] == {
        "requested": True, "total": 1, "pre_success": 1,
        "post_applicable": 0, "post_success": 0, "complete_pairs": 0,
        "post_not_applicable": 1, "post_not_requested": 0,
    }
    warnings = _quality_warnings([], [connection], pcap)
    assert [(item["code"], item["severity"]) for item in warnings] == [
        ("PCAP_POST_NOT_APPLICABLE", "info"),
    ]


def test_applicable_missing_post_pcap_remains_a_quality_failure():
    connection = {
        "connection_id": "conn-11111111111111111111111111111111",
        "match": {"status": "matched", "method": "exact_pre_flow"},
        "post_flow": {
            "network": "tcp", "src_ip": "192.0.2.1", "src_port": 51000,
            "dst_ip": "203.0.113.1", "dst_port": 443,
        },
    }
    pcap = {
        "split_mode": "unique_connections",
        "connections": [{
            "connection_id": connection["connection_id"],
            "pre_proxy": {"status": "success"},
            "post_proxy": {"status": "empty"},
        }],
    }

    quality = analysis_quality([], [connection], pcap)
    assert quality["pcap_extraction"]["post_applicable"] == 1
    assert quality["pcap_extraction"]["post_success"] == 0
    warnings = _quality_warnings([], [connection], pcap)
    assert [(item["code"], item["severity"]) for item in warnings] == [
        ("PCAP_POST_UNAVAILABLE", "warning"),
    ]



def test_rejected_egress_is_conserved_as_not_applicable_in_layered_coverage():
    connection = {
        "connection_id": "conn-11111111111111111111111111111111",
        "match": {"status": "matched", "method": "exact_pre_flow"},
        "post_flow": None,
        "shared": False,
        "egress": {"outcome": "rejected"},
    }
    core = {
        "conn_id": "mihomo-reject",
        "post_flow": None,
        "shared": False,
        "egress_outcome": "rejected",
    }

    coverage = layered_coverage([], [connection], [core])
    assert coverage["page_attributed"]["logical_flows"] == {
        "total": 1,
        "with_post_flow": 0,
        "shared": 0,
        "missing_post_flow": 0,
        "explicit_no_socket": 1,
        "failed_before_socket": 0,
        "local_not_applicable": 0,
        "unexpected_missing": 0,
        "not_applicable_outcome": 1,
    }
    assert coverage["capture_global"]["core_logical_flows"] == {
        "total": 1,
        "with_post_flow": 0,
        "shared": 0,
        "missing_post_flow": 0,
        "explicit_no_socket": 1,
        "failed_before_socket": 0,
        "local_not_applicable": 0,
        "unexpected_missing": 0,
        "not_applicable_outcome": 1,
    }
    assert coverage["page_attributed"]["unmatched_reasons"] == {}
    assert coverage["capture_global"]["unmatched_reasons"] == {}


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
            "post_proxy": {"status": "not_applicable"},
        }],
    }), encoding="utf-8")

    summary = json.loads(
        persist_analysis_artifacts(tmp_path, SESSION_ID).summary.read_text(
            encoding="utf-8",
        )
    )

    assert summary["quality_state"] == "passed"
    assert [item["code"] for item in summary["warnings"]] == [
        "PCAP_POST_NOT_APPLICABLE", "LOCAL_ENDPOINT_UNAVAILABLE",
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
        "requested": True, "total": 1, "pre_success": 1,
        "post_applicable": 0, "post_success": 0, "complete_pairs": 0,
        "post_not_applicable": 1, "post_not_requested": 0,
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
        "explicit_no_socket": 0,
        "failed_before_socket": 0,
        "local_not_applicable": 0,
        "unexpected_missing": 0,
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


def test_capture_global_error_classifies_local_proxy_timeout_and_dns():
    base = FlowTuple(
        network="tcp", src_ip="198.18.0.1", src_port=40000,
        dst_ip="198.18.0.2", dst_port=443, complete=True,
    )
    local = FlowMapping(
        "local", "", base, None, "dial_error",
        "dial tcp 127.0.0.1:25120: connect: connection refused",
    )
    proxy_timeout = FlowMapping(
        "proxy", "", base, None, "dial_error",
        "node.example:24191 connect error: context deadline exceeded",
    )
    dns = FlowMapping(
        "dns", "", base, None, "resolve_error", "could not find ip",
    )
    assert _mapping_targets_loopback(local) is True
    assert _mapping_error_class(proxy_timeout) == "timeout"
    assert _mapping_error_class(dns) == "dns_resolution"


def test_target_document_entirely_non_network_is_inconclusive():
    records = [{
        "request_id": "1.1",
        "url": "https://example.com/",
        "resource_type": "Document",
        "network_observation": "disk_cache",
    }]
    assert _target_document_non_network(records, "https://example.com/") == 1
    records.append({
        "request_id": "1.2",
        "url": "https://example.com/",
        "resource_type": "Document",
        "network_observation": "network",
    })
    assert _target_document_non_network(records, "https://example.com/") == 0


def test_local_connection_is_detected_without_page_request_attribution():
    connection_id = "conn-background-local"
    connections = [{
        "connection_id": connection_id,
        "pre_flow": {"src_ip": "198.18.0.1", "dst_ip": "198.18.0.2"},
        "post_flow": None,
        "terminal": {
            "status": "dial_error",
            "error": "dial tcp 127.0.0.1:25120: connect: connection refused",
        },
    }]
    assert _local_connection_ids([], connections) == {connection_id}


def test_storage_summary_counts_only_capture_inputs(tmp_path):
    from traffictracer.analyze.artifacts import _storage_summary

    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "tun.pcap").write_bytes(b"p" * 7)
    (raw / "netlog.json").write_bytes(b"n" * 11)
    (raw / "mihomo-trace.jsonl").write_bytes(b"t" * 13)
    (raw / "capture-context.json").write_bytes(b"c" * 5)
    published = tmp_path / "analysis"
    published.mkdir()
    (published / "old.json").write_bytes(b"x" * 101)
    results = tmp_path / "results"
    results.mkdir()
    (results / "connection-index-v2.json").write_bytes(b"r" * 17)

    storage = _storage_summary(tmp_path, results)
    assert storage == {
        "capture_bytes": 36,
        "raw_packet_capture_bytes": 7,
        "netlog_bytes": 11,
        "mihomo_trace_bytes": 13,
        "trace_snapshot_bytes": 0,
        "trace_snapshot_logical_bytes": None,
        "trace_snapshot_compression_ratio": None,
        "trace_archive_bytes": 0,
        "capture_metadata_bytes": 5,
        "analysis_result_bytes_before_summary": 17,
        "compression": "none",
    }


def test_reanalysis_cannot_hide_failed_packet_coverage(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "capture-context.json").write_text(json.dumps({
        "packet_coverage": {"session_id": SESSION_ID, "status": "failed", "drops": "unknown"},
    }))
    result = persist_analysis_artifacts(tmp_path, SESSION_ID)
    summary = json.loads(result.summary.read_text())
    assert summary["quality_state"] == "failed"
    assert summary["analysis_integrity"]["page_attributed"]["state"] == "failed"
    assert any(w["code"] == "PACKET_CAPTURE_INCOMPLETE" for w in summary["warnings"])


def test_summary_surfaces_bounded_playback_quality(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    playback = {
        "provider": "youtube",
        "quality": "degraded",
        "reason": "PRIMARY_DURATION_BELOW_TARGET",
        "primary_goal_met": False,
        "primary_content_seconds": 12,
        "desired_primary_seconds": 25,
    }
    (raw / "capture-context.json").write_text(
        json.dumps({"playback": playback}), encoding="utf-8"
    )
    artifacts = persist_analysis_artifacts(tmp_path, SESSION_ID)
    summary = json.loads(artifacts.summary.read_text(encoding="utf-8"))
    assert summary["playback"] == playback
    assert summary["quality_state"] == "passed"
    assert summary["analysis_integrity"]["page_attributed"]["state"] == "passed"
    assert summary["scenario_outcome"] == {
        "kind": "youtube_playback",
        "state": "degraded",
        "reason": "PRIMARY_DURATION_BELOW_TARGET",
        "primary_content_observed": True,
        "primary_goal_met": False,
        "primary_content_seconds": 12,
        "desired_primary_seconds": 25,
        "ad_observed": None,
        "skippable_ad_observed": None,
        "skip_confirmed": None,
    }


def test_playback_scenario_fails_only_when_primary_is_not_observed(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    playback = {
        "provider": "youtube",
        "quality": "unavailable",
        "reason": "PRIMARY_CONTENT_NOT_OBSERVED",
        "primary_content_observed": False,
        "primary_goal_met": False,
        "primary_content_seconds": 0,
        "desired_primary_seconds": 25,
        "ad_observed": True,
        "skippable_ad_observed": False,
        "skip_confirmed": False,
    }
    (raw / "capture-context.json").write_text(
        json.dumps({"playback": playback}), encoding="utf-8"
    )
    artifacts = persist_analysis_artifacts(tmp_path, SESSION_ID)
    summary = json.loads(artifacts.summary.read_text(encoding="utf-8"))
    assert summary["quality_state"] == "passed"
    assert summary["scenario_outcome"]["state"] == "failed"
    assert summary["scenario_outcome"]["primary_content_observed"] is False
    assert summary["scenario_outcome"]["ad_observed"] is True


def test_carrier_summary_counts_shared_fan_out_without_duplication():
    path = _flow(
        "udp", "192.0.2.10", 55000, "203.0.113.20", 443,
        "post_proxy", shared=True,
    )
    binding = {
        "carrier_id": "carrier-1", "mode": "shared",
        "physical_paths": [path],
    }
    items = [
        {"egress_outcome": "proxy", "carrier_binding": binding},
        {"egress_outcome": "proxy", "carrier_binding": binding},
        {"egress_outcome": "proxy"},
        {"egress_outcome": "direct"},
    ]

    summary = _carrier_binding_summary(items)

    assert summary["logical_proxy_flows"] == 3
    assert summary["bound_logical_flows"] == 2
    assert summary["missing_binding"] == 1
    assert summary["shared_carrier_count"] == 1
    assert summary["shared_carrier_max_fan_out"] == 2
    assert summary["physical_carriers_observed"] == 1


def test_capture_context_summaries_report_protocol_and_inbound_mismatch(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "capture-context.json").write_text(json.dumps({
        "proxy_protocol": {
            "mode": "strict_single",
            "expected_protocol": "hysteria2",
            "protocols": ["hysteria2"],
            "runtime_observation": {
                "protocols": ["hysteria2"],
                "consistency": "match",
                "proxy_dial_events": 4,
            },
        },
        "inbound": {
            "mode": "tun", "interface": "Meta",
            "expected_core_name": "DEFAULT-TUN",
        },
    }), encoding="utf-8")
    items = [{
        "inbound_name": "MIXED-IN",
        "pre_flow": _flow(
            "tcp", "127.0.0.1", 40000, "127.0.0.1", 7890, "pre_proxy",
        ),
    }]

    assert _capture_protocol_summary(tmp_path)["consistency"] == "match"
    inbound = _capture_inbound_summary(tmp_path, items)
    assert inbound["mismatched_flows"] == 1
    assert inbound["loopback_flows"] == 1
    assert inbound["consistency"] == "mismatch"

    local_on_expected_tun = _capture_inbound_summary(tmp_path, [{
        "inbound_name": "DEFAULT-TUN",
        "pre_flow": _flow(
            "tcp", "127.0.0.1", 40000, "127.0.0.1", 7890, "pre_proxy",
        ),
    }])
    assert local_on_expected_tun["mismatched_flows"] == 0
    assert local_on_expected_tun["loopback_flows"] == 1
    assert local_on_expected_tun["consistency"] == "match_with_local"
