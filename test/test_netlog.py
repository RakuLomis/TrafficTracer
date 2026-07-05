"""Tests for NetLog 5-tuple extraction."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.analyze.netlog import _parse_addr, FiveTupleData, DomainConnections


def test_parse_addr_ipv4():
    assert _parse_addr("127.0.0.1:51891") == ("127.0.0.1", 51891)
    assert _parse_addr("192.168.1.1:0") == ("192.168.1.1", 0)


def test_parse_addr_ipv6():
    assert _parse_addr("[::1]:443") == ("::1", 443)
    assert _parse_addr("[2001:db8::1]:8443") == ("2001:db8::1", 8443)


def test_parse_addr_empty():
    assert _parse_addr("") == ("", 0)
    assert _parse_addr("no-port") == ("no-port", 0)


def test_domain_connections_creation():
    ft = FiveTupleData(src_ip="127.0.0.1", src_port=51891,
                        dst_ip="127.0.0.1", dst_port=7890, protocol="")
    dc = DomainConnections(
        name="https://www.example.com",
        site="https://example.com",
        relation="same_site",
        five_tuples=[ft],
    )
    assert dc.name == "https://www.example.com"
    assert dc.relation == "same_site"
    assert dc.five_tuples[0].src_port == 51891


if __name__ == "__main__":
    test_parse_addr_ipv4()
    test_parse_addr_ipv6()
    test_parse_addr_empty()
    test_domain_connections_creation()
    print("\n✓ All NetLog extractor tests passed!")
