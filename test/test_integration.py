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


def test_cdp_integration():
    from traffictracer.analyze.cdp_attribution import parse_cdp_attribution
    from traffictracer.analyze.netlog_transport import trace_transport
    from traffictracer.analyze.correlator import correlate_v2

    tmpdir = tempfile.mkdtemp()

    cdp_data = {
        "visit_url": "https://www.bilibili.com",
        "targets": [{"target_id": "T1", "type": "page", "url": "https://www.bilibili.com"}],
        "requests": [
            {"request_id": "1.1", "target_id": "T1", "frame_id": "F1",
             "url": "https://www.bilibili.com/",
             "resource_type": "Document", "timestamp": 100.0,
             "target_type": "page"},
            {"request_id": "1.2", "target_id": "T1", "frame_id": "F1",
             "url": "https://unknown-cdn.net/video.m4s",
             "resource_type": "Media", "timestamp": 101.0,
             "connection_id": 17, "remote_ip": "5.6.7.8", "remote_port": 443,
             "connection_reused": True, "target_type": "page"},
        ],
        "websockets": [],
    }
    cdp_path = os.path.join(tmpdir, "cdp.json")
    with open(cdp_path, "w") as f:
        json.dump(cdp_data, f)

    netlog = {
        "constants": {
            "logFormatVersion": 1,
            "timeTickOffset": "1329000000000",
            "logSourceType": {
                "URL_REQUEST": 1, "HTTP_STREAM_JOB": 5,
                "HTTP_PROXY_CONNECT_JOB": 10,
            },
            "logEventPhase": {"PHASE_BEGIN": 0, "PHASE_END": 1, "PHASE_NONE": 2},
        },
        "events": [
            {"time": "1000", "type": 0, "phase": 0,
             "source": {"id": 100, "type": 1},
             "params": {"url": "https://unknown-cdn.net/video.m4s",
                         "source_dependency": {"id": 200, "type": 5}}},
            {"time": "1200", "type": 50, "phase": 2,
             "source": {"id": 300, "type": 10},
             "params": {"local_address": "198.18.0.1:49812",
                         "remote_address": "5.6.7.8:443",
                         "source_dependency": {"id": 200, "type": 5}}},
        ],
    }
    netlog_path = os.path.join(tmpdir, "netlog.json")
    with open(netlog_path, "w") as f:
        json.dump(netlog, f)

    trace_path = os.path.join(tmpdir, "trace.jsonl")
    with open(trace_path, "w") as f:
        f.write('{"ts":"","type":"tcp_connect","conn_id":"c1",'
                '"src":"198.18.0.1:49812","dst":"5.6.7.8:443",'
                '"host":"unknown-cdn.net"}\n')
        f.write('{"ts":"","type":"tcp_proxy_dial","conn_id":"c1",'
                '"proxy":"HK","proxy_type":"vless","proxy_addr":"10.0.0.1:443",'
                '"out_src":"192.168.5.101:53652"}\n')

    attributed = parse_cdp_attribution(cdp_path)
    assert len(attributed) == 2

    transport = trace_transport(attributed, netlog_path)
    assert len(transport) >= 1

    from traffictracer.analyze.mihomo_log import parse_tracing_log
    mihomo_conns = parse_tracing_log(trace_path)

    result = correlate_v2(
        transport, mihomo_conns,
        visit_url="https://www.bilibili.com",
        domain="bilibili.com",
        cdp_request_count=len(attributed),
    )

    assert result.domain == "bilibili.com"
    assert len(result.flows) >= 1

    cdn_flow = None
    for fl in result.flows:
        if "unknown-cdn.net" in fl.url:
            cdn_flow = fl
            break
    assert cdn_flow is not None
    assert cdn_flow.pre_proxy_src == "198.18.0.1:49812"
    assert cdn_flow.post_proxy_src == "192.168.5.101:53652"
    assert cdn_flow.relation == "cross_site"

    import shutil
    shutil.rmtree(tmpdir)
    print("  \u2713 CDP integration test pass")


if __name__ == "__main__":
    test_analysis_integration()
    test_cdp_integration()
    print("\n\u2713 All integration tests passed!")
