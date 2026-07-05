"""Integration test — end-to-end analysis pipeline with synthetic data."""

import sys
import os
import json
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pathlib import Path
from traffictracer.analyze.netlog import extract_five_tuples
from traffictracer.analyze.mihomo_log import parse_tracing_log
from traffictracer.analyze.correlator import correlate
from traffictracer.analyze.pcap_splitter import build_tshark_filter


def test_analysis_integration():
    tmpdir = tempfile.mkdtemp()

    netlog = {
        "constants": {
            "logFormatVersion": 1,
            "timeTickOffset": "1329000000000",
            "logEventTypes": {
                "REQUEST_ALIVE": 0, "URL_REQUEST_START_JOB": 11,
                "TCP_CONNECT": 4, "SOCKET_ALIVE": 3, "SSL_CONNECT": 50,
            },
            "logSourceType": {
                "URL_REQUEST": 1, "TRANSPORT_CONNECT_JOB": 2,
                "SOCKET": 3, "HTTP_STREAM_JOB": 5,
                "HTTP_PROXY_CONNECT_JOB": 10, "TCP_STREAM_ATTEMPT": 20,
            },
            "logEventPhase": {"PHASE_BEGIN": 0, "PHASE_END": 1, "PHASE_NONE": 2},
            "clientInfo": {"name": "integration-test"},
        },
        "events": [
            {"time": "1000", "type": 0, "phase": 0, "source": {"id": 100, "type": 1},
             "params": {"url": "https://www.example.com/",
                        "source_dependency": {"id": 200, "type": 5}}},
            {"time": "1100", "type": 21, "phase": 2, "source": {"id": 200, "type": 5},
             "params": {"group_id": "https://www.example.com <https://example.com same_site>"}},
            {"time": "1200", "type": 50, "phase": 2, "source": {"id": 300, "type": 10},
             "params": {"local_address": "127.0.0.1:55555",
                        "remote_address": "127.0.0.1:7890",
                        "source_dependency": {"id": 200, "type": 5}}},
        ],
    }
    netlog_path = os.path.join(tmpdir, "netlog_example.com.json")
    with open(netlog_path, "w") as f:
        json.dump(netlog, f)

    trace_path = os.path.join(tmpdir, "mihomo_trace.jsonl")
    with open(trace_path, "w") as f:
        f.write('{"ts":"","type":"tcp_connect","conn_id":"c1",'
                '"src":"127.0.0.1:55555","dst":"127.0.0.1:7890",'
                '"host":"www.example.com"}\n')
        f.write('{"ts":"","type":"tcp_proxy_dial","conn_id":"c1",'
                '"proxy":"Proxy","proxy_type":"ss","proxy_addr":"1.2.3.4:443",'
                '"out_src":"192.168.1.100:41234"}\n')

    netlog_conns = extract_five_tuples(netlog_path, "example.com")
    mihomo_conns = parse_tracing_log(trace_path)

    assert len(mihomo_conns) == 1
    assert "c1" in mihomo_conns

    result = correlate(netlog_conns, mihomo_conns, "example.com")
    assert result.domain == "example.com"

    for flow in result.flows:
        if flow.pre_proxy.src_port == 55555:
            assert flow.pre_proxy.src_ip == "127.0.0.1"
            f = build_tshark_filter(flow.pre_proxy, "src")
            assert "tcp.srcport==55555" in f

    import shutil
    shutil.rmtree(tmpdir)
    print("  \u2713 integration test pass")


if __name__ == "__main__":
    test_analysis_integration()
    print("\n\u2713 All integration tests passed!")
