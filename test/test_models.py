# test/test_models.py
"""Tests for shared data model types."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.models import (
    AttributedRequest,
    TransportConnection,
    CorrelatedFlowV2,
    VisitCorrelation,
)


def test_attributed_request_defaults():
    req = AttributedRequest(
        request_id="921.18",
        target_id="ABC",
        frame_id="F1",
        url="https://cdn.example.net/video.m4s",
        resource_type="Media",
        timestamp=123456.123,
    )
    assert req.connection_id is None
    assert req.remote_ip == ""
    assert req.remote_port == 0
    assert req.connection_reused is False
    assert req.target_type == "page"
    assert req.loader_id == ""
    assert req.initiator_type == ""


def test_attributed_request_with_connection():
    req = AttributedRequest(
        request_id="1.1",
        target_id="T1",
        frame_id="F1",
        url="https://api.bilibili.com/x",
        resource_type="XHR",
        timestamp=100.0,
        connection_id=17,
        remote_ip="1.2.3.4",
        remote_port=443,
        connection_reused=True,
        target_type="page",
        loader_id="L1",
        initiator_type="script",
    )
    assert req.connection_id == 17
    assert req.connection_reused is True


def test_transport_connection():
    tc = TransportConnection(
        netlog_source_id=300,
        url="https://cdn.example.net/video.m4s",
        src_ip="198.18.0.1",
        src_port=49812,
        dst_ip="1.2.3.4",
        dst_port=443,
        protocol="HTTP2",
        request_ids=["921.18", "921.19"],
    )
    assert len(tc.request_ids) == 2
    assert tc.src_ip == "198.18.0.1"


def test_correlated_flow_v2():
    flow = CorrelatedFlowV2(
        url="https://cdn.example.net/video.m4s",
        resource_type="Media",
        target_type="page",
        relation="cross_site",
        pre_proxy_src="198.18.0.1:49812",
        pre_proxy_dst="1.2.3.4:443",
        post_proxy_src="192.168.5.101:53652",
        post_proxy_dst="1.2.3.4:443",
        protocol="HTTP2",
        request_ids=["921.18"],
        connection_reused=True,
    )
    assert flow.relation == "cross_site"
    assert flow.connection_reused is True


def test_visit_correlation():
    vc = VisitCorrelation(
        visit_url="https://www.bilibili.com",
        domain="bilibili.com",
        flows=[],
        cdp_request_count=42,
        netlog_connection_count=17,
    )
    assert vc.cdp_request_count == 42
    assert len(vc.flows) == 0


if __name__ == "__main__":
    test_attributed_request_defaults()
    test_attributed_request_with_connection()
    test_transport_connection()
    test_correlated_flow_v2()
    test_visit_correlation()
    print("\n✓ All model tests passed!")
