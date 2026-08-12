"""Tests for analysis pipeline."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import tempfile
import shutil
from pathlib import Path

import pytest

from traffictracer.analyze.pipeline import run_analysis, _result_to_dict, _result_v2_to_dict
from traffictracer.jobs.cancellation import CancellationToken
from traffictracer.jobs.cancellation import CancelledError
from traffictracer.jobs.progress import ProgressReporter


def test_result_v2_to_dict():
    from traffictracer.models import VisitCorrelation, CorrelatedFlowV2
    vc = VisitCorrelation(
        visit_url="https://www.bilibili.com",
        domain="bilibili.com",
        flows=[
            CorrelatedFlowV2(
                url="https://cdn.example.net/video.m4s",
                resource_type="Media",
                target_type="page",
                relation="cross_site",
                pre_proxy_src="198.18.0.1:49812",
                pre_proxy_dst="1.2.3.4:443",
                post_proxy_src="192.168.5.101:53652",
                post_proxy_dst="10.0.0.1:443",
                protocol="HTTP2",
                request_ids=["1.1"],
                connection_reused=True,
            ),
        ],
        cdp_request_count=42,
        netlog_connection_count=17,
    )
    d = _result_v2_to_dict(vc)
    assert d["visit_url"] == "https://www.bilibili.com"
    assert d["cdp_request_count"] == 42
    assert len(d["flows"]) == 1
    assert d["flows"][0]["url"] == "https://cdn.example.net/video.m4s"
    assert d["flows"][0]["request_ids"] == ["1.1"]


def test_analysis_cdp_path():
    """Full analysis with CDP data present."""
    tmpdir = tempfile.mkdtemp()
    session = os.path.join(tmpdir, "session")
    os.makedirs(os.path.join(session, "captures", "bilibili.com", "video-mainpage_1"))
    os.makedirs(os.path.join(session, "logs"))
    os.makedirs(os.path.join(session, "results"))

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
             "params": {"url": "https://cdn.example.net/video.m4s",
                         "source_dependency": {"id": 200, "type": 5}}},
            {"time": "1200", "type": 50, "phase": 2,
             "source": {"id": 300, "type": 10},
             "params": {"local_address": "198.18.0.1:49812",
                         "remote_address": "1.2.3.4:443",
                         "source_dependency": {"id": 200, "type": 5}}},
        ],
    }
    with open(os.path.join(session, "logs", "netlog_bilibili.com_video-mainpage_1.json"), "w") as f:
        json.dump(netlog, f)

    cdp_data = {
        "visit_url": "https://www.bilibili.com",
        "targets": [{"target_id": "T1", "type": "page", "url": "https://www.bilibili.com"}],
        "requests": [
            {"request_id": "1.1", "target_id": "T1", "frame_id": "F1",
             "url": "https://cdn.example.net/video.m4s",
             "resource_type": "Media", "timestamp": 100.0,
             "connection_id": 17, "remote_ip": "1.2.3.4", "remote_port": 443,
             "connection_reused": True, "target_type": "page"},
        ],
        "websockets": [],
    }
    with open(os.path.join(session, "logs", "cdp_bilibili.com_video-mainpage_1.json"), "w") as f:
        json.dump(cdp_data, f)

    with open(os.path.join(session, "logs", "mihomo_trace_bilibili.com_video-mainpage_1.jsonl"), "w") as f:
        f.write('{"ts":"","type":"tcp_connect","conn_id":"c1",'
                '"src":"198.18.0.1:49812","dst":"1.2.3.4:443",'
                '"host":"cdn.example.net"}\n')
        f.write('{"ts":"","type":"tcp_proxy_dial","conn_id":"c1",'
                '"proxy":"HK","proxy_type":"vless","proxy_addr":"10.0.0.1:443",'
                '"out_src":"192.168.5.101:53652"}\n')

    progress = []
    corr_path = run_analysis(
        session,
        progress=ProgressReporter("analysis-job", progress.append, min_interval=0),
        cancellation=CancellationToken(),
    )

    assert os.path.exists(corr_path)
    with open(corr_path) as f:
        data = json.load(f)

    assert "bilibili.com" in data
    domain_data = data["bilibili.com"]
    assert "flows" in domain_data
    assert len(domain_data["flows"]) >= 1
    flow = domain_data["flows"][0]
    assert flow["url"] == "https://cdn.example.net/video.m4s"
    assert flow["pre_proxy_src"] == "198.18.0.1:49812"
    connection_index = json.loads(
        Path(session, "results", "connection-index-v2.json").read_text(encoding="utf-8")
    )
    request_index = json.loads(
        Path(session, "results", "request-index-v2.json").read_text(encoding="utf-8")
    )
    assert len(connection_index["items"]) == 1
    assert len(request_index["items"]) == 1
    assert request_index["items"][0]["connection_id"] == connection_index["items"][0]["connection_id"]
    assert connection_index["items"][0]["match"]["method"] == "netlog_socket"
    assert [event.stage for event in progress] == [
        "analyze.cdp",
        "analyze.netlog",
        "analyze.mihomo",
        "analyze.correlate",
        "analyze.split",
        "analyze.write",
    ]

    shutil.rmtree(tmpdir)
    print("  ✓ CDP-path analysis test pass")


def test_analysis_checks_cancellation_between_parse_stages(tmp_path, monkeypatch):
    import traffictracer.analyze.pipeline as module

    run_dir = tmp_path / "captures" / "example.com" / "all_1"
    run_dir.mkdir(parents=True)
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "netlog_example.com_all_1.json").write_text("{}", encoding="utf-8")
    (logs / "mihomo_trace_example.com_all_1.jsonl").write_text(
        "{}\n", encoding="utf-8"
    )
    token = CancellationToken()

    def cancel_during_mihomo(path, **kwargs):
        token.cancel("cancel between analysis stages")
        return {}

    monkeypatch.setattr(module, "parse_tracing_log", cancel_during_mihomo)
    events = []
    with pytest.raises(CancelledError, match="cancel between analysis stages"):
        run_analysis(
            str(tmp_path),
            progress=ProgressReporter("analysis-job", events.append, min_interval=0),
            cancellation=token,
        )
    assert [event.stage for event in events] == [
        "analyze.cdp",
        "analyze.netlog",
        "analyze.mihomo",
    ]
    assert not (tmp_path / "results" / "correlation.json").exists()


def test_truncated_netlog_repair_never_mutates_raw_capture(tmp_path):
    from traffictracer.analyze.pipeline import _fix_netlog

    raw = tmp_path / "netlog.json"
    original = '{"events": [{"type": 1},'
    raw.write_text(original, encoding="utf-8")
    repaired = Path(_fix_netlog(str(raw)))
    try:
        assert raw.read_text(encoding="utf-8") == original
        assert json.loads(repaired.read_text(encoding="utf-8"))["events"]
    finally:
        repaired.unlink(missing_ok=True)


def test_analysis_output_directory_cannot_escape_session(tmp_path):
    session = tmp_path / "session"
    (session / "captures").mkdir(parents=True)
    (session / "logs").mkdir()
    with pytest.raises(ValueError, match="escapes"):
        run_analysis(
            str(session),
            output_dir=tmp_path / "outside",
        )


if __name__ == "__main__":
    test_result_v2_to_dict()
    test_analysis_cdp_path()
    print("\n✓ All analysis pipeline tests passed!")
