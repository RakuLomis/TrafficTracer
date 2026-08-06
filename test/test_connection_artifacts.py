"""Tests for connection-centric request and transport artifacts."""

import json

from traffictracer.analyze.connection_artifacts import (
    persist_connection_artifacts,
    persist_pcap_index,
)
from traffictracer.analyze.artifacts import layered_coverage
from traffictracer.analyze.pcap_splitter import (
    ConnectionPcapResult,
    PcapSideResult,
)
from traffictracer.models import AttributedRequest, CorrelatedFlowV2, FlowTerminal, FlowTuple, VisitCorrelation


SESSION_ID = "5027aee9-c6e4-41de-8625-7ea0869a3307"
CONNECTION_ID = "conn-11111111111111111111111111111111"


def _request(request_id: str) -> AttributedRequest:
    return AttributedRequest(
        request_id=request_id,
        target_id="target",
        frame_id="frame",
        url="https://cdn.example.net/repeated.js",
        resource_type="Script",
        timestamp=100.0,
    )


def test_requests_are_separate_from_one_ambiguous_shared_connection(tmp_path):
    pre = FlowTuple(
        "tcp", "198.18.0.1", 44000, "9.9.9.9", 443,
        key="tcp|198.18.0.1:44000|9.9.9.9:443",
        complete=True,
        source="netlog",
        scope="pre_proxy",
    )
    flow = CorrelatedFlowV2(
        url="https://cdn.example.net/repeated.js",
        resource_type="Script",
        target_type="page",
        relation="cross_site",
        pre_proxy_src=pre.src,
        pre_proxy_dst=pre.dst,
        post_proxy_src="",
        post_proxy_dst="",
        protocol="HTTP2",
        request_ids=["1.1", "1.2"],
        connection_reused=True,
        pre_flow=pre,
        post_flow=None,
        match_status="ambiguous",
        match_confidence=0.85,
        stable_connection_id=CONNECTION_ID,
        match_method="netlog_socket",
        match_candidates=[
            {"connection_id": "conn-22222222222222222222222222222222", "native_id": "a", "score": 0.85, "evidence": ["source_and_destination", "time_unavailable"]},
            {"connection_id": "conn-33333333333333333333333333333333", "native_id": "b", "score": 0.85, "evidence": ["source_and_destination", "time_unavailable"]},
        ],
        netlog_source_id=17,
        terminal=FlowTerminal("dial_error", "dial", "timeout", 0, 0, 123),
        match_reason="multiple_candidates",
        match_evidence=["top_score_tie"],
    )
    result = VisitCorrelation(
        visit_url="https://example.com/",
        domain="example.com",
        flows=[flow],
        cdp_request_count=2,
        netlog_connection_count=1,
        requests=[_request("1.1"), _request("1.2")],
    )

    artifacts = persist_connection_artifacts(tmp_path, SESSION_ID, [result])
    connections = json.loads(artifacts.connection_index.read_text(encoding="utf-8"))["items"]
    requests = json.loads(artifacts.request_index.read_text(encoding="utf-8"))["items"]

    assert len(connections) == 1
    assert connections[0]["netlog_source_id"] == 17
    assert connections[0]["terminal"]["status"] == "dial_error"
    assert connections[0]["terminal"]["stage"] == "dial"
    assert connections[0]["connection_id"] == CONNECTION_ID
    assert connections[0]["request_ids"] == ["1.1", "1.2"]
    assert connections[0]["match"]["status"] == "ambiguous"
    assert connections[0]["match"]["evidence"] == ["top_score_tie"]
    assert len(requests) == 2
    assert requests[0]["url"] == requests[1]["url"]
    assert {item["connection_id"] for item in requests} == {CONNECTION_ID}

    pcap_path = tmp_path / "results" / "pcap" / CONNECTION_ID / "pre.pcap"
    pcap_path.parent.mkdir(parents=True)
    pcap_path.write_bytes(b"pcap-data")
    index_path = persist_pcap_index(
        tmp_path,
        SESSION_ID,
        artifacts.generation_id,
        "unique_connections",
        [
            ConnectionPcapResult(
                connection_id=CONNECTION_ID,
                protocol="tcp",
                request_ids=("1.1", "1.2"),
                pre_proxy=PcapSideResult(
                    "success",
                    "tcp.stream eq 1",
                    packet_count=2,
                    byte_count=128,
                    artifact_id="pcap-conn-111-pre",
                    path=str(pcap_path),
                ),
                post_proxy=PcapSideResult(
                    "empty",
                    "tcp.stream eq 2",
                ),
            )
        ],
    )
    pcap_index = json.loads(index_path.read_text(encoding="utf-8"))
    assert pcap_index["analysis_generation_id"] == artifacts.generation_id
    assert pcap_index["connections"][0]["pre_proxy"]["path"] == (
        f"results/pcap/{CONNECTION_ID}/pre.pcap"
    )
    assert pcap_index["coverage"]["browser_requests"] == {
        "total": 2,
        "matched": 2,
        "ambiguous": 0,
        "unmatched": 0,
        "non_network": 0,
    }
    assert pcap_index["coverage"]["transport_connections"]["ambiguous"] == 1
    assert pcap_index["coverage"]["core_logical_flows"] == {
        "total": 0,
        "with_post_flow": 0,
        "shared": 0,
        "missing_post_flow": 0,
    }
    assert pcap_index["coverage"]["unmatched_reasons"] == {
        "multiple_candidates": 1,
    }


def test_cached_request_is_not_counted_as_missing_transport(tmp_path):
    result = VisitCorrelation(
        visit_url="https://example.com/",
        domain="example.com",
        flows=[],
        cdp_request_count=1,
        netlog_connection_count=0,
        requests=[AttributedRequest(
            "cache.1", "target", "frame", "https://example.com/app.js",
            "Script", 100.0, connection_id=0, response_status=200,
            from_disk_cache=True,
        )],
    )

    artifacts = persist_connection_artifacts(tmp_path, SESSION_ID, [result])
    request = json.loads(
        artifacts.request_index.read_text(encoding="utf-8")
    )["items"][0]
    assert request["network_observation"] == "disk_cache"
    assert request["connection_id"] is None
    assert request["attribution"]["unmatched_reason"] == "non_network_response"
    coverage = layered_coverage([request], [])
    assert coverage["browser_requests"] == {
        "total": 1,
        "matched": 0,
        "ambiguous": 0,
        "unmatched": 0,
        "non_network": 1,
    }
    assert coverage["unmatched_reasons"] == {}


def test_egress_chain_resolves_direct_and_splits_sharing_semantics(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "proxy-info.json").write_text(json.dumps([
        {
            "group": "Bilibili", "node": "DIRECT", "type": "Direct",
            "network": "", "server": "", "port": "",
        },
    ]), encoding="utf-8")
    pre = FlowTuple(
        "tcp", "198.18.0.1", 44000, "198.18.0.2", 443,
        key="tcp|198.18.0.1:44000|198.18.0.2:443", complete=True,
    )
    post = FlowTuple(
        "tcp", "192.168.5.101", 45000, "203.0.113.10", 443,
        key="tcp|192.168.5.101:45000|203.0.113.10:443", complete=True,
    )
    flow = CorrelatedFlowV2(
        url="https://www.bilibili.com/", resource_type="Document",
        target_type="page", relation="same_site",
        pre_proxy_src=pre.src, pre_proxy_dst=pre.dst,
        post_proxy_src=post.src, post_proxy_dst=post.dst,
        protocol="HTTPS", request_ids=["1.1", "1.2"],
        connection_reused=True, pre_flow=pre, post_flow=post,
        match_status="matched", match_confidence=1.0,
        stable_connection_id=CONNECTION_ID, match_method="exact_pre_flow",
        match_candidates=[{
            "connection_id": CONNECTION_ID, "native_id": "native",
            "score": 1.0, "evidence": ["normalized_pre_flow"],
        }], match_evidence=["normalized_pre_flow"],
        proxy="Bilibili", proxy_type="Selector",
    )
    result = VisitCorrelation(
        visit_url="https://www.bilibili.com/", domain="bilibili.com",
        flows=[flow], requests=[_request("1.1"), _request("1.2")],
    )

    artifacts = persist_connection_artifacts(tmp_path, SESSION_ID, [result])
    connection = json.loads(
        artifacts.connection_index.read_text(encoding="utf-8")
    )["items"][0]
    assert connection["egress"] == {
        "mode": "direct",
        "policy": "Bilibili",
        "selection_chain": ["Bilibili", "DIRECT"],
        "selected_node": "DIRECT",
        "selected_type": "Direct",
        "evidence": "mihomo_trace_and_session_proxy_snapshot",
    }
    assert connection["sharing"] == {
        "request_multiplexed": True,
        "post_flow_shared": False,
        "outer_connection_reused": False,
    }


def test_request_prefers_exact_complete_pipeline_over_ambiguous_quic(tmp_path):
    request_id = "media.1"
    tcp_pre = FlowTuple(
        "tcp", "198.18.0.1", 60362, "198.18.0.56", 443,
        key="tcp|198.18.0.1:60362|198.18.0.56:443", complete=True,
        source="metadata_snapshot", scope="pre_proxy",
    )
    tcp_post = FlowTuple(
        "tcp", "192.168.5.101", 37450, "61.220.99.41", 24101,
        key="tcp|192.168.5.101:37450|61.220.99.41:24101", complete=True,
        source="dialer_socket", scope="post_proxy",
    )
    exact = CorrelatedFlowV2(
        url="https://media.example/videoplayback?rn=1",
        resource_type="Media", target_type="page", relation="cross_site",
        pre_proxy_src=tcp_pre.src, pre_proxy_dst=tcp_pre.dst,
        post_proxy_src=tcp_post.src, post_proxy_dst=tcp_post.dst,
        protocol="HTTPS", request_ids=[request_id], pre_flow=tcp_pre,
        post_flow=tcp_post, match_status="matched", match_confidence=0.95,
        stable_connection_id="conn-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        match_method="exact_pre_flow",
        match_candidates=[
            {"connection_id": "conn-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "native_id": "a", "score": 0.95, "evidence": ["normalized_pre_flow"]},
        ],
        match_evidence=["normalized_pre_flow"], terminal=FlowTerminal("closed"),
    )
    quic_pre = FlowTuple(
        "udp", "198.18.0.1", 60366, "198.18.0.56", 443,
        key="udp|198.18.0.1:60366|198.18.0.56:443", complete=True,
        source="netlog", scope="pre_proxy",
    )
    quic = CorrelatedFlowV2(
        url="https://media.example/videoplayback?rn=1",
        resource_type="Media", target_type="page", relation="cross_site",
        pre_proxy_src=quic_pre.src, pre_proxy_dst=quic_pre.dst,
        post_proxy_src="", post_proxy_dst="", protocol="QUIC",
        request_ids=[request_id], pre_flow=quic_pre, post_flow=None,
        match_status="ambiguous", match_confidence=0.4,
        stable_connection_id="conn-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        match_method="host_time", match_reason="multiple_candidates",
        match_candidates=[
            {"connection_id": "conn-cccccccccccccccccccccccccccccccc", "native_id": "c", "score": 0.4, "evidence": ["destination_host"]},
            {"connection_id": "conn-dddddddddddddddddddddddddddddddd", "native_id": "d", "score": 0.4, "evidence": ["destination_host"]},
        ],
        match_evidence=["top_score_tie"],
    )
    result = VisitCorrelation(
        visit_url="https://example.com/", domain="example.com",
        flows=[exact, quic], cdp_request_count=1, netlog_connection_count=2,
        requests=[AttributedRequest(
            request_id, "target", "frame",
            "https://media.example/videoplayback?rn=1", "Media", 100.0,
        )],
    )

    artifacts = persist_connection_artifacts(tmp_path, SESSION_ID, [result])
    requests = json.loads(
        artifacts.request_index.read_text(encoding="utf-8")
    )["items"]

    assert requests[0]["connection_id"] == exact.stable_connection_id
    assert requests[0]["candidate_connection_ids"] == [
        exact.stable_connection_id,
        quic.stable_connection_id,
    ]
    assert requests[0]["attribution"]["status"] == "matched"


def test_empty_quic_retry_selects_packet_backed_tcp_resource(tmp_path):
    request_id = "media.2"
    tcp_pre = FlowTuple(
        "tcp", "198.18.0.1", 60362, "198.18.0.56", 443,
        key="tcp|198.18.0.1:60362|198.18.0.56:443", complete=True,
    )
    tcp_post = FlowTuple(
        "tcp", "192.168.5.101", 37450, "61.220.99.41", 24101,
        key="tcp|192.168.5.101:37450|61.220.99.41:24101", complete=True,
    )
    tcp = CorrelatedFlowV2(
        url="https://media.example/videoplayback?id=video&rn=1&alr=yes",
        resource_type="Media", target_type="page", relation="cross_site",
        pre_proxy_src=tcp_pre.src, pre_proxy_dst=tcp_pre.dst,
        post_proxy_src=tcp_post.src, post_proxy_dst=tcp_post.dst,
        protocol="HTTPS", request_ids=["media.1"], pre_flow=tcp_pre,
        post_flow=tcp_post, match_status="matched", match_confidence=0.95,
        stable_connection_id="conn-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        match_method="exact_pre_flow", terminal=FlowTerminal("closed"),
        match_candidates=[
            {"connection_id": "conn-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "native_id": "a", "score": 0.95, "evidence": ["normalized_pre_flow"]},
        ], match_evidence=["normalized_pre_flow"],
    )
    quic_pre = FlowTuple(
        "udp", "198.18.0.1", 60366, "198.18.0.56", 443,
        key="udp|198.18.0.1:60366|198.18.0.56:443", complete=True,
    )
    quic = CorrelatedFlowV2(
        url="https://media.example/videoplayback?id=video&rn=2&alr=yes",
        resource_type="Media", target_type="page", relation="cross_site",
        pre_proxy_src=quic_pre.src, pre_proxy_dst=quic_pre.dst,
        post_proxy_src="", post_proxy_dst="", protocol="QUIC",
        request_ids=[request_id], pre_flow=quic_pre, post_flow=None,
        match_status="ambiguous", match_confidence=0.4,
        stable_connection_id="conn-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        match_method="host_time", match_reason="multiple_candidates",
        match_candidates=[
            {"connection_id": "conn-cccccccccccccccccccccccccccccccc", "native_id": "c", "score": 0.4, "evidence": ["destination_host"]},
            {"connection_id": "conn-dddddddddddddddddddddddddddddddd", "native_id": "d", "score": 0.4, "evidence": ["destination_host"]},
        ], match_evidence=["top_score_tie"],
    )
    result = VisitCorrelation(
        visit_url="https://example.com/", domain="example.com",
        flows=[tcp, quic], cdp_request_count=2, netlog_connection_count=2,
        requests=[
            AttributedRequest("media.1", "T", "F", tcp.url, "Media", 100.0),
            AttributedRequest(request_id, "T", "F", quic.url, "Media", 101.0),
        ],
    )
    pcap_results = [
        ConnectionPcapResult(
            tcp.stable_connection_id, "tcp", ("media.1",),
            PcapSideResult("success", "tcp", packet_count=10, byte_count=1000),
            PcapSideResult("success", "tcp", packet_count=12, byte_count=1100),
        ),
        ConnectionPcapResult(
            quic.stable_connection_id, "udp", (request_id,),
            PcapSideResult("empty", "udp"),
            PcapSideResult("not_requested", ""),
        ),
    ]

    artifacts = persist_connection_artifacts(
        tmp_path, SESSION_ID, [result], pcap_results=pcap_results,
    )
    requests = json.loads(
        artifacts.request_index.read_text(encoding="utf-8")
    )["items"]
    retry = next(item for item in requests if item["request_id"] == request_id)

    assert retry["connection_id"] == tcp.stable_connection_id
    assert retry["candidate_connection_ids"] == [
        tcp.stable_connection_id, quic.stable_connection_id,
    ]
    assert retry["attribution"]["evidence"][-2:] == [
        "transport_race_resolved", "pcap_observed",
    ]
    connections = json.loads(
        artifacts.connection_index.read_text(encoding="utf-8")
    )["items"]
    canonical = next(
        item for item in connections
        if item["connection_id"] == tcp.stable_connection_id
    )
    assert canonical["request_ids"] == ["media.1", "media.2"]
    assert canonical["sharing"]["request_multiplexed"] is True
