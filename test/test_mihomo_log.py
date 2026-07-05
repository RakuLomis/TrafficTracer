"""Tests for Mihomo tracing log parser."""

import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.analyze.mihomo_log import (
    parse_tracing_log, MihomoConnection, TcpConnect, TcpProxyDial, TcpClose,
)


def test_parse_tracing_log():
    content = """\
{"ts":"2025-07-05T10:00:00Z","type":"tcp_connect","conn_id":"conn-1","src":"127.0.0.1:55555","dst":"127.0.0.1:7890","host":"www.example.com"}
{"ts":"2025-07-05T10:00:01Z","type":"tcp_proxy_dial","conn_id":"conn-1","proxy":"Proxy","proxy_type":"ss","proxy_addr":"1.2.3.4:443","out_src":"192.168.1.100:41234"}
{"ts":"2025-07-05T10:00:10Z","type":"tcp_close","conn_id":"conn-1","bytes_up":1024,"bytes_down":4096,"duration_ms":9000}
{"ts":"2025-07-05T10:00:00Z","type":"tcp_connect","conn_id":"conn-2","src":"127.0.0.1:55556","dst":"127.0.0.1:7890","host":"cdn.example.com"}
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write(content)
        tmp = f.name

    try:
        conns = parse_tracing_log(tmp)
        assert len(conns) == 2
        assert "conn-1" in conns
        c1 = conns["conn-1"]
        assert c1.connect is not None
        assert c1.connect.src == "127.0.0.1:55555"
        assert c1.connect.host == "www.example.com"
        assert c1.proxy_dial is not None
        assert c1.proxy_dial.out_src == "192.168.1.100:41234"
        assert c1.close is not None
        assert c1.close.bytes_up == 1024
        assert c1.close.bytes_down == 4096

        c2 = conns["conn-2"]
        assert c2.connect is not None
        assert c2.proxy_dial is None
        assert c2.close is None
    finally:
        os.unlink(tmp)

    print("  ✓ Mihomo log parsing pass")


def test_parse_empty_log():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write("\n")
        tmp = f.name
    try:
        conns = parse_tracing_log(tmp)
        assert len(conns) == 0
    finally:
        os.unlink(tmp)


if __name__ == "__main__":
    test_parse_tracing_log()
    test_parse_empty_log()
    print("\n✓ All Mihomo log parser tests passed!")
