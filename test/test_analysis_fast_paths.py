import random
import struct
from types import SimpleNamespace

import pytest

from parser import dependency_graph as graph
from traffictracer.analyze.pcap_metrics import classic_pcap_metrics


@pytest.mark.parametrize("order", ["<", ">"])
def test_pcap_metrics_use_wire_lengths(tmp_path, order):
    p = tmp_path / "input.pcap"
    p.write_bytes(struct.pack(order + "IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
                  + struct.pack(order + "IIII", 0, 0, 3, 80) + b"abc")
    assert classic_pcap_metrics(p) == (1, 80)
    p.write_bytes(p.read_bytes()[:-1])
    with pytest.raises(ValueError):
        classic_pcap_metrics(p)


@pytest.mark.parametrize("order", ["<", ">"])
def test_pcapng_metrics_and_unknown_fallback(tmp_path, order):
    def block(kind, body):
        length = len(body) + 12
        return struct.pack(order + "II", kind, length) + body + struct.pack(order + "I", length)
    section = block(0x0A0D0D0A, struct.pack(order + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    packet = block(6, struct.pack(order + "IIIII", 0, 0, 0, 3, 80) + b"abc\0")
    p = tmp_path / "input.pcapng"
    p.write_bytes(section + packet)
    assert classic_pcap_metrics(p) == (1, 80)
    p.write_bytes(section + packet + block(3, b"\0" * 4))
    assert classic_pcap_metrics(p) is None
    p.write_bytes(section + packet[:-1])
    with pytest.raises(ValueError):
        classic_pcap_metrics(p)


def test_dependency_branch_pruning_preserves_exhaustive_scores(monkeypatch):
    rng = random.Random(42)
    monkeypatch.setattr(graph, "_entry_has_complete_endpoints", lambda e: e.endpoint)
    def reference(sid, entries, visited, depth):
        if sid in visited or depth <= 0 or sid not in entries:
            return -10000
        e = entries[sid]
        seen = visited | {sid}
        own = 1000 if e.endpoint else 0
        return max([own] + [reference(d, entries, seen, depth - 1) - 10
                           for d in graph._dependency_ids(e) if d not in seen])
    for _ in range(80):
        entries = {i: SimpleNamespace(source_type=-1, endpoint=rng.random() < .3,
                   entries=[{"params": {"source_dependency": {"id": rng.randrange(10)}}}
                            for _ in range(3)]) for i in range(10)}
        for sid in entries:
            assert graph._dependency_path_score(sid, entries, set(), 5) == reference(sid, entries, set(), 5)


def test_children_index_deduplicates_edges():
    dep = {"params": {"source_dependency": {"id": 2}}}
    assert graph._build_children_index({1: SimpleNamespace(entries=[dep] * 100)}) == {2: [1]}


def test_health_terminal_snapshot_and_exception(tmp_path):
    import json
    from traffictracer.analyze.health import analysis_health
    progress = SimpleNamespace(stage=None)
    with analysis_health(tmp_path, "test-job", progress, interval=.01):
        pass
    path = tmp_path / ".analysis-health.json"
    assert json.loads(path.read_text())["state"] == "completed"
    with pytest.raises(ValueError):
        with analysis_health(tmp_path, "failure-job", progress):
            raise ValueError("test")
    assert json.loads(path.read_text())["state"] == "ValueError"


def test_analysis_command_cancellation_reaps_child(tmp_path):
    import os
    import sys
    from threading import Timer
    from traffictracer.analyze.process import analysis_process_scope, run_analysis_command
    from traffictracer.jobs.cancellation import CancellationToken, InterruptedError
    token = CancellationToken()
    pidfile = tmp_path / "child.pid"
    timer = Timer(.5, token.interrupt)
    timer.start()
    try:
        with analysis_process_scope(token), pytest.raises(InterruptedError):
            run_analysis_command([sys.executable, "-c",
                "import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(30)", str(pidfile)])
    finally:
        timer.cancel()
        timer.join()
    if pidfile.exists():
        with pytest.raises(ProcessLookupError):
            os.kill(int(pidfile.read_text()), 0)


def test_analysis_command_capture_output():
    import sys
    from traffictracer.analyze.process import analysis_process_scope, run_analysis_command
    from traffictracer.jobs.cancellation import CancellationToken
    with analysis_process_scope(CancellationToken()):
        result = run_analysis_command([sys.executable, "-c", "print('ok')"], capture_output=True, text=True)
    assert result.returncode == 0 and result.stdout == "ok\n"


def test_health_records_actual_progress_and_restores_context(tmp_path):
    import json
    from traffictracer.analyze.health import analysis_health, record_analysis_progress
    progress = SimpleNamespace(stage=None)
    with analysis_health(tmp_path, "progress-job", progress):
        record_analysis_progress("netlog.trace_sources", 128, 256)
    activity = json.loads((tmp_path / ".analysis-health.json").read_text())["activity"]
    assert activity["operation"] == "netlog.trace_sources"
    assert activity["processed"] == 128 and activity["total"] == 256
    assert activity["seconds_since_progress"] >= 0
    # A later job must not inherit the previous parser's counters.
    with analysis_health(tmp_path, "next-job", progress):
        pass
    activity = json.loads((tmp_path / ".analysis-health.json").read_text())["activity"]
    assert "operation" not in activity
    record_analysis_progress("outside_scope", 999)


def test_analysis_checkpoint_propagates_interrupt():
    from traffictracer.analyze.process import analysis_process_scope, analysis_checkpoint
    from traffictracer.jobs.cancellation import CancellationToken, InterruptedError
    token = CancellationToken()
    token.interrupt()
    with analysis_process_scope(token), pytest.raises(InterruptedError):
        analysis_checkpoint()
    analysis_checkpoint()  # scope restored


@pytest.mark.parametrize("cdp", [False, True])
@pytest.mark.parametrize("failure", [MemoryError, RuntimeError])
def test_non_json_failure_does_not_attempt_netlog_repair(tmp_path, monkeypatch, cdp, failure):
    from traffictracer.analyze import pipeline
    path = tmp_path / "cdp.json"
    path.write_text('{"visit_url":"https://example.com/","requests":[]}')
    def fail(*args, **kwargs):
        raise failure("not malformed JSON")
    def unexpected_repair(*args, **kwargs):
        pytest.fail("non-JSON failures must not trigger whole-file repair")
    monkeypatch.setattr(pipeline, "_fix_netlog", unexpected_repair)
    monkeypatch.setattr(pipeline, "trace_transport" if cdp else "extract_five_tuples", fail)
    with pytest.raises(failure):
        if cdp:
            pipeline._analyze_cdp_path(str(path), "unused", "unused", {}, "example.com", "test", None)
        else:
            pipeline._analyze_domain_path("unused", {}, "example.com", "test")


def test_loaded_cdp_matches_file_parser(tmp_path):
    import json
    from traffictracer.analyze.cdp_attribution import parse_cdp_attribution, parse_cdp_attribution_data
    data = {"requests": [
        {"request_id": "1", "url": "https://example.com/", "timestamp": 1},
        {"request_id": "1", "url": "https://example.com/next", "timestamp": 2},
    ]}
    path = tmp_path / "cdp.json"
    path.write_text(json.dumps(data))
    assert parse_cdp_attribution(str(path)) == parse_cdp_attribution_data(data)


def test_event_normalization_progress_can_cancel():
    from parser.event_processor import process_events
    from parser.constants import NetLogConstants
    observed = []
    def progress(operation, processed, total):
        observed.append((operation, processed, total))
        if processed == 1024:
            raise RuntimeError("cancel sentinel")
    with pytest.raises(RuntimeError, match="cancel sentinel"):
        process_events([{}] * 2048, NetLogConstants({}), progress=progress)
    assert observed == [("normalize_events", 0, 2048), ("normalize_events", 1024, 2048)]


def test_analysis_command_timeout_and_bounded_diagnostics():
    import subprocess
    import sys
    from traffictracer.analyze.process import analysis_process_scope, run_analysis_command
    from traffictracer.jobs.cancellation import CancellationToken
    with analysis_process_scope(CancellationToken()):
        with pytest.raises(subprocess.TimeoutExpired):
            run_analysis_command([sys.executable, "-c", "import time; time.sleep(30)"], timeout=.05)
        result = run_analysis_command([sys.executable, "-c", "import sys; sys.stderr.write('x'*1000000); print('ok')"], capture_output=True, text=True)
    assert result.stdout == "ok\n"
    assert len(result.stderr) == 8192


def test_analysis_command_streamed_metrics():
    import sys
    from traffictracer.analyze.process import analysis_process_scope, run_analysis_command
    from traffictracer.analyze.pcap_splitter import _count_frame_lengths
    from traffictracer.jobs.cancellation import CancellationToken
    with analysis_process_scope(CancellationToken()):
        result = run_analysis_command([sys.executable, "-c", "print('80\\n120\\n')"], capture_output=True, text=True, stdout_consumer=_count_frame_lengths)
    assert result.stdout == (2, 200)


def test_graph_property_cache_is_scoped_to_one_traversal():
    entry = SimpleNamespace(entries=[])
    with graph.dependency_checkpoints(lambda: None):
        assert not graph._entry_has_complete_endpoints(entry)
        assert graph._dependency_ids(entry) == []
    entry.entries.append({"params": {"local_address": "127.0.0.1:1", "remote_address": "127.0.0.2:2", "source_dependency": {"id": 4}}})
    with graph.dependency_checkpoints(lambda: None):
        assert graph._entry_has_complete_endpoints(entry)
        assert graph._dependency_ids(entry) == [4]


def test_health_stall_warning_is_not_a_job_failure(tmp_path):
    import json
    from traffictracer.analyze.health import analysis_health
    with analysis_health(tmp_path, "stall", SimpleNamespace(stage=None), stall_warning_seconds=0):
        snapshot = json.loads((tmp_path / ".analysis-health.json").read_text())
        assert snapshot["activity"]["stall_warning"]
        assert snapshot["state"] == "running"
    assert json.loads((tmp_path / ".analysis-health.json").read_text())["state"] == "completed"
