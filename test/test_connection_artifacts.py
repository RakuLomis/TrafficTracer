"""Tests for connection-centric request and transport artifacts."""

import json

from traffictracer.analyze.connection_artifacts import persist_connection_artifacts
from traffictracer.models import AttributedRequest, CorrelatedFlowV2, FlowTuple, VisitCorrelation


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
    assert connections[0]["connection_id"] == CONNECTION_ID
    assert connections[0]["request_ids"] == ["1.1", "1.2"]
    assert connections[0]["match"]["status"] == "ambiguous"
    assert connections[0]["match"]["evidence"] == ["top_score_tie"]
    assert len(requests) == 2
    assert requests[0]["url"] == requests[1]["url"]
    assert {item["connection_id"] for item in requests} == {CONNECTION_ID}
