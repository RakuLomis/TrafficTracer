"""INT-009 gate for shared-connection deduplication and conservative coverage."""

import json
from pathlib import Path
import subprocess

from traffictracer.analyze.connection_artifacts import (
    persist_connection_artifacts,
    persist_pcap_index,
)
from traffictracer.analyze.pcap_splitter import split_flows_v2
from traffictracer.models import (
    AttributedRequest,
    CorrelatedFlowV2,
    FlowTuple,
    VisitCorrelation,
)
from traffictracer.session.manifest import SessionManifest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "test" / "fixtures" / "integration" / "shared-connection.json"
LEGACY_MANIFEST = ROOT / "test" / "fixtures" / "contracts" / "session-valid.json"


def _tuple(payload, scope):
    return FlowTuple(
        **payload,
        key=(
            f"{payload['network']}|{payload['src_ip']}:{payload['src_port']}"
            f"|{payload['dst_ip']}:{payload['dst_port']}"
        ),
        complete=True,
        source="fixture",
        scope=scope,
        shared=scope == "post_proxy",
    )


def test_shared_connection_fixture_gates_indexes_pcaps_coverage_and_v1(
    tmp_path,
    monkeypatch,
):
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    pre = _tuple(fixture["pre_flow"], "pre_proxy")
    post = _tuple(fixture["post_flow"], "post_proxy")
    flows = [
        CorrelatedFlowV2(
            url=request["url"],
            resource_type="Script",
            target_type="page",
            relation="cross_site",
            pre_proxy_src=pre.src,
            pre_proxy_dst=pre.dst,
            post_proxy_src=post.src,
            post_proxy_dst=post.dst,
            protocol="HTTP2",
            request_ids=[request["request_id"]],
            connection_reused=True,
            pre_flow=pre,
            post_flow=post,
            match_status="matched",
            match_confidence=1.0,
            stable_connection_id=fixture["connection_id"],
            match_method="exact_pre_flow",
            match_candidates=[{
                "connection_id": fixture["connection_id"],
                "score": 1.0,
                "evidence": ["normalized_pre_flow"],
            }],
            match_evidence=["normalized_pre_flow"],
        )
        for request in fixture["requests"]
    ]
    requests = [
        AttributedRequest(
            request_id=request["request_id"],
            target_id="target",
            frame_id="frame",
            url=request["url"],
            resource_type="Script",
            timestamp=float(index),
        )
        for index, request in enumerate(fixture["requests"])
    ]
    result = VisitCorrelation(
        visit_url="https://example.test/",
        domain="example.test",
        flows=flows,
        cdp_request_count=8,
        netlog_connection_count=1,
        requests=requests,
    )
    (tmp_path / "logs").mkdir()
    artifacts = persist_connection_artifacts(
        tmp_path,
        fixture["session_id"],
        [result],
    )
    calls = []

    def tshark(command, **kwargs):
        calls.append(command)
        if "-w" in command:
            Path(command[-1]).write_bytes(b"pcap" + b"x" * 32)
            return subprocess.CompletedProcess(command, 0)
        return subprocess.CompletedProcess(command, 0, stdout="60\n70\n")

    monkeypatch.setattr(
        "traffictracer.analyze.pcap_splitter.subprocess.run",
        tshark,
    )
    pcap_results = split_flows_v2(
        result,
        "tun.pcap",
        "phys.pcap",
        str(tmp_path / "results" / "pcap"),
    )
    pcap_index_path = persist_pcap_index(
        tmp_path,
        fixture["session_id"],
        artifacts.generation_id,
        "unique_connections",
        pcap_results,
    )

    request_index = json.loads(artifacts.request_index.read_text(encoding="utf-8"))
    connection_index = json.loads(
        artifacts.connection_index.read_text(encoding="utf-8")
    )
    pcap_index = json.loads(pcap_index_path.read_text(encoding="utf-8"))
    assert len(request_index["items"]) == 8
    assert len(connection_index["items"]) == 1
    assert len(connection_index["items"][0]["request_ids"]) == 8
    assert len([call for call in calls if "-w" in call]) == 2
    assert len(pcap_index["connections"]) == 1
    assert len(pcap_index["connections"][0]["request_ids"]) == 8
    for name in ("browser_requests", "transport_connections"):
        partition = pcap_index["coverage"][name]
        assert (
            partition["matched"]
            + partition["ambiguous"]
            + partition["unmatched"]
            == partition["total"]
        )

    legacy = SessionManifest.load(LEGACY_MANIFEST)
    assert legacy.schema_version == 1
    assert legacy.read_only is True
