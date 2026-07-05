"""Tests for correlation engine."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.analyze.netlog import FiveTupleData, DomainConnections
from traffictracer.analyze.mihomo_log import (
    MihomoConnection, TcpConnect, TcpProxyDial, TcpClose,
)
from traffictracer.analyze.correlator import correlate, CorrelationResult, CorrelatedFlow


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


if __name__ == "__main__":
    test_correlate_matching()
    test_correlate_no_match()
    print("\n✓ All correlator tests passed!")
