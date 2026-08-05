"""Tests for correlation engine."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.analyze.netlog import FiveTupleData, DomainConnections
from traffictracer.analyze.mihomo_log import (
    MihomoConnection, TcpConnect, TcpProxyDial, TcpClose,
)
from traffictracer.analyze.correlator import correlate, CorrelationResult, CorrelatedFlow
from traffictracer.models import FlowTuple, TransportConnection, VisitCorrelation, CorrelatedFlowV2
from traffictracer.analyze.correlator import correlate_v2


def test_correlate_matching():
    netlog_conns = [
        DomainConnections(
            name="https://www.example.com",
            site="https://example.com",
            relation="same_site",
            five_tuples=[
                FiveTupleData("127.0.0.1", 55555, "127.0.0.1", 7890, "tcp"),
            ],
        ),
    ]

    mihomo_conns = {
        "conn-1": MihomoConnection(
            conn_id="conn-1",
            connect=TcpConnect(
                ts="", conn_id="conn-1",
                src="127.0.0.1:55555", dst="127.0.0.1:7890",
                host="www.example.com",
            ),
            proxy_dial=TcpProxyDial(
                ts="", conn_id="conn-1",
                proxy="Proxy", proxy_type="ss",
                proxy_addr="1.2.3.4:443",
                out_src="192.168.1.100:41234",
            ),
            close=None,
        ),
    }

    result = correlate(netlog_conns, mihomo_conns, "example.com")
    assert result.domain == "example.com"
    assert len(result.flows) == 1
    assert result.flows[0].pre_proxy.src_port == 55555
    assert result.flows[0].post_proxy.src_ip == "192.168.1.100"
    assert result.flows[0].post_proxy.src_port == 41234
    assert result.flows[0].post_proxy.dst_ip == "1.2.3.4"
    assert result.flows[0].post_proxy.dst_port == 443


def test_correlate_connect_only():
    netlog_conns = [
        DomainConnections(
            name="https://direct.example.com",
            site="https://direct.example.com",
            relation="same_site",
            five_tuples=[
                FiveTupleData("10.0.0.1", 40000, "93.184.216.34", 80, "tcp"),
            ],
        ),
    ]

    mihomo_conns = {
        "conn-2": MihomoConnection(
            conn_id="conn-2",
            connect=TcpConnect(
                ts="", conn_id="conn-2",
                src="10.0.0.1:40000", dst="93.184.216.34:80",
                host="direct.example.com",
            ),
            proxy_dial=None,
            close=None,
        ),
    }

    result = correlate(netlog_conns, mihomo_conns, "direct.example.com")
    assert len(result.flows) == 1
    assert result.flows[0].pre_proxy.src_ip == "10.0.0.1"
    assert result.flows[0].pre_proxy.src_port == 40000
    assert result.flows[0].post_proxy.src_ip == ""
    assert result.flows[0].post_proxy.src_port == 0
    assert result.flows[0].post_proxy.dst_ip == "93.184.216.34"
    assert result.flows[0].post_proxy.dst_port == 80


def test_correlate_no_match():
    netlog_conns = [
        DomainConnections(
            name="https://no-match.com",
            site="https://no-match.com",
            relation="same_site",
            five_tuples=[
                FiveTupleData("127.0.0.1", 99999, "127.0.0.1", 7890, "tcp"),
            ],
        ),
    ]
    mihomo_conns = {
        "conn-1": MihomoConnection(
            conn_id="conn-1",
            connect=TcpConnect(
                ts="", conn_id="conn-1",
                src="127.0.0.1:55555", dst="127.0.0.1:7891",
                host="other.example.com",
            ),
            proxy_dial=None,
            close=None,
        ),
    }
    result = correlate(netlog_conns, mihomo_conns, "no-match.com")
    assert len(result.flows) == 0


def test_correlate_v2_proxy_match():
    transport_conns = [
        TransportConnection(
            netlog_source_id=300,
            url="https://cdn.example.net/video.m4s",
            src_ip="198.18.0.1", src_port=49812,
            dst_ip="1.2.3.4", dst_port=443,
            protocol="HTTP2",
            request_ids=["1.1", "1.2"],
        ),
    ]

    mihomo_conns = {
        "c1": MihomoConnection(
            conn_id="c1",
            connect=TcpConnect(
                ts="", conn_id="c1",
                src="198.18.0.1:49812", dst="1.2.3.4:443",
                host="cdn.example.net",
            ),
            proxy_dial=TcpProxyDial(
                ts="", conn_id="c1",
                proxy="HK", proxy_type="vless",
                proxy_addr="10.0.0.1:443",
                out_src="192.168.5.101:53652",
            ),
            close=None,
        ),
    }

    result = correlate_v2(
        transport_conns, mihomo_conns,
        visit_url="https://www.bilibili.com",
        domain="bilibili.com",
        cdp_request_count=2,
    )

    assert isinstance(result, VisitCorrelation)
    assert result.domain == "bilibili.com"
    assert len(result.flows) == 1
    flow = result.flows[0]
    assert isinstance(flow, CorrelatedFlowV2)
    assert flow.pre_proxy_src == "198.18.0.1:49812"
    assert flow.pre_proxy_dst == "1.2.3.4:443"
    assert flow.post_proxy_src == "192.168.5.101:53652"
    assert flow.post_proxy_dst == "10.0.0.1:443"
    assert set(flow.request_ids) == {"1.1", "1.2"}


def test_correlate_v2_direct_connection():
    transport_conns = [
        TransportConnection(
            netlog_source_id=100,
            url="https://www.bilibili.com/",
            src_ip="198.18.0.1", src_port=50000,
            dst_ip="223.111.250.57", dst_port=443,
            protocol="TCP",
            request_ids=["2.1"],
        ),
    ]

    mihomo_conns = {
        "c2": MihomoConnection(
            conn_id="c2",
            connect=TcpConnect(
                ts="", conn_id="c2",
                src="198.18.0.1:50000", dst="223.111.250.57:443",
                host="www.bilibili.com",
            ),
            proxy_dial=None,
            close=TcpClose(
                "", "c2", 0, 0, 123,
                status="dial_error", stage="dial", error="timeout",
            ),
        ),
    }

    result = correlate_v2(
        transport_conns, mihomo_conns,
        visit_url="https://www.bilibili.com",
        domain="bilibili.com",
        cdp_request_count=1,
    )

    assert len(result.flows) == 1
    flow = result.flows[0]
    assert flow.post_proxy_src == ""
    assert flow.post_proxy_dst == "223.111.250.57:443"
    assert flow.terminal is not None
    assert flow.terminal.status == "dial_error"
    assert flow.terminal.stage == "dial"
    assert flow.terminal.error == "timeout"


def test_correlate_v2_no_match():
    transport_conns = [
        TransportConnection(
            netlog_source_id=100,
            url="https://nomatch.com/",
            src_ip="10.0.0.1", src_port=99999,
            dst_ip="10.0.0.2", dst_port=80,
            protocol="TCP",
            request_ids=["3.1"],
        ),
    ]
    mihomo_conns = {
        "c1": MihomoConnection(
            conn_id="c1",
            connect=TcpConnect(
                ts="", conn_id="c1",
                src="10.0.0.1:11111", dst="10.0.0.2:80",
                host="other.com",
            ),
            proxy_dial=None, close=None,
        ),
    }

    result = correlate_v2(
        transport_conns, mihomo_conns,
        visit_url="https://nomatch.com",
        domain="nomatch.com",
        cdp_request_count=1,
    )
    assert len(result.flows) == 1
    assert result.flows[0].match_status == "unmatched"
    assert result.flows[0].match_reason == "insufficient_time"


if __name__ == "__main__":
    test_correlate_matching()
    test_correlate_connect_only()
    test_correlate_no_match()
    test_correlate_v2_proxy_match()
    test_correlate_v2_direct_connection()
    test_correlate_v2_no_match()
    print("\n✓ All correlator tests passed!")


def test_correlate_v2_prefers_normalized_key():
    pre = FlowTuple("tcp", "198.18.0.1", 44000, "9.9.9.9", 443,
                    key="tcp|198.18.0.1:44000|9.9.9.9:443", complete=True)
    post = FlowTuple("tcp", "192.0.2.10", 55000, "203.0.113.8", 8443,
                     key="tcp|192.0.2.10:55000|203.0.113.8:8443", complete=True)
    transport = TransportConnection(1, "https://example.com", "198.18.0.1", 44000,
                                    "9.9.9.9", 443, "HTTP2")
    connection = MihomoConnection(
        "normalized", TcpConnect("", "normalized", "legacy-wrong", "legacy-wrong", "example.com", pre_flow=pre),
        TcpProxyDial("", "normalized", "P", "ss", "legacy-wrong", "legacy-wrong",
                     post_flow=post, outer_conn_id="outer"), None,
    )
    flow = correlate_v2([transport], {"normalized": connection}, "https://example.com", "example.com").flows[0]
    assert flow.match_status == "matched"
    assert flow.match_method == "exact_pre_flow"
    assert flow.match_confidence == 0.95
    assert flow.post_proxy_src == "192.0.2.10:55000"
    assert flow.post_proxy_dst == "203.0.113.8:8443"
    assert flow.outer_conn_id == "outer"
