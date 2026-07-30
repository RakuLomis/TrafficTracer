"""Tests for pcap splitter filter generation."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.analyze.netlog import FiveTupleData
from traffictracer.analyze.pcap_splitter import build_tshark_filter, build_flow_tuple_filter, _sanitize_name
from traffictracer.models import FlowTuple


def test_build_filter_src():
    ft = FiveTupleData("192.168.1.100", 41234, "1.2.3.4", 443, "tcp")
    f = build_tshark_filter(ft, "src")
    assert "ip.src==192.168.1.100" in f
    assert "tcp.srcport==41234" in f


def test_build_filter_dst():
    ft = FiveTupleData("192.168.1.100", 41234, "1.2.3.4", 443, "tcp")
    f = build_tshark_filter(ft, "dst")
    assert "ip.src==192.168.1.100" in f
    assert "tcp.port==41234" in f


def test_build_filter_empty():
    ft = FiveTupleData("", 0, "", 0, "")
    f = build_tshark_filter(ft, "src")
    assert f == ""


def test_sanitize_name():
    assert _sanitize_name("https://www.example.com/") == "www.example.com"
    assert _sanitize_name("https://api.example.com") == "api.example.com"
    assert _sanitize_name("http://localhost:8080/path") == "localhost:8080/path"


if __name__ == "__main__":
    test_build_filter_src()
    test_build_filter_dst()
    test_build_filter_empty()
    test_sanitize_name()
    print("\n✓ All pcap splitter tests passed!")


def test_normalized_filter_is_bidirectional_udp_ipv6():
    flow = FlowTuple(
        network="udp", src_ip="2001:db8::1", src_port=50000,
        dst_ip="2001:db8::2", dst_port=443, complete=True, key="key",
    )
    display_filter = build_flow_tuple_filter(flow)
    assert "udp" in display_filter
    assert "ipv6.src==2001:db8::1" in display_filter
    assert "udp.srcport==50000" in display_filter
    assert "ipv6.src==2001:db8::2" in display_filter
    assert "udp.dstport==50000" in display_filter
