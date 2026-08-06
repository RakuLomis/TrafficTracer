"""Tests for stable connection terminal error classes."""

import json

from traffictracer.analyze.connection_artifacts import persist_connection_artifacts
from traffictracer.models import CorrelatedFlowV2, FlowTerminal, FlowTuple, VisitCorrelation


SESSION_ID = "5027aee9-c6e4-41de-8625-7ea0869a3307"


def _record(tmp_path, dst_ip: str, error: str) -> dict:
    pre = FlowTuple(
        "tcp", "198.18.0.1", 44000, dst_ip, 443,
        key=f"tcp|198.18.0.1:44000|{dst_ip}:443", complete=True,
    )
    flow = CorrelatedFlowV2(
        url="https://example.com/", resource_type="Document",
        target_type="page", relation="same_site",
        pre_proxy_src=pre.src, pre_proxy_dst=pre.dst,
        post_proxy_src="", post_proxy_dst="", protocol="HTTPS",
        pre_flow=pre, match_status="unmatched", match_reason="no_candidate",
        stable_connection_id="conn-11111111111111111111111111111111",
        terminal=FlowTerminal("dial_error", "dial", error),
    )
    artifacts = persist_connection_artifacts(
        tmp_path, SESSION_ID,
        [VisitCorrelation("https://example.com/", "example.com", flows=[flow])],
    )
    return json.loads(
        artifacts.connection_index.read_text(encoding="utf-8")
    )["items"][0]


def test_ipv4_timeout_has_stable_error_class(tmp_path):
    record = _record(tmp_path, "198.18.0.39", "i/o timeout")
    assert record["terminal"]["error_class"] == "ipv4_timeout"


def test_ipv6_unreachable_has_stable_error_class(tmp_path):
    record = _record(tmp_path, "2001:db8::39", "network is unreachable")
    assert record["terminal"]["error_class"] == "ipv6_unreachable"
