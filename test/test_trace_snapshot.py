import hashlib
import json
import pytest

from traffictracer.capture.trace_snapshot import publish_trace_snapshot
from traffictracer.capture.trace_snapshot import prepare_analysis_trace, analysis_trace_path
from traffictracer.jobs.models import CaptureJobOptions


def test_retention_default_and_explicit_false_survive_serialization():
    assert CaptureJobOptions().retain_trace_journal is True
    options = CaptureJobOptions(retain_trace_journal=False)
    assert CaptureJobOptions(**options.to_dict()).retain_trace_journal is False
    with pytest.raises(ValueError):
        CaptureJobOptions(retain_trace_journal="false")


def test_snapshot_uses_confirmed_prefix_and_preserves_tail(tmp_path):
    source, target = tmp_path / "live.jsonl", tmp_path / "snapshot.jsonl"
    prefix = b'{"type":"trace_barrier"}\n'
    source.write_bytes(prefix + b'{"type":"tcp_close"}\n')
    result = publish_trace_snapshot(source, target, len(prefix))
    assert target.read_bytes() == prefix
    assert result["sha256"] == hashlib.sha256(prefix).hexdigest()
    with source.open("ab") as stream:
        stream.write(b'{"type":"udp_close"}\n')
    assert target.read_bytes() == prefix
    assert b"tcp_close" in source.read_bytes()


def test_snapshot_never_overwrites_previous_generation(tmp_path):
    source, target = tmp_path / "live", tmp_path / "snapshot"
    source.write_bytes(b"{}\n")
    target.write_bytes(b"original")
    with pytest.raises(FileExistsError):
        publish_trace_snapshot(source, target, 3)
    assert target.read_bytes() == b"original"
    assert not list(tmp_path.glob(".trace-snapshot-*"))


@pytest.mark.parametrize("boundary", [0, -1, True, 2, 100])
def test_invalid_or_partial_boundary_is_not_published(tmp_path, boundary):
    source, target = tmp_path / "live", tmp_path / "snapshot"
    source.write_bytes(b"{}\n")
    with pytest.raises(ValueError):
        publish_trace_snapshot(source, target, boundary)
    assert not target.exists()
    assert source.read_bytes() == b"{}\n"
    assert not list(tmp_path.glob(".trace-snapshot-*"))


def test_analysis_freezes_available_tail_and_resume_reuses_input(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    context = {"trace_policy": {"immutable_analysis_input": True, "retain_journal": False},
               "trace_boundary": {"byte_size": 3, "event_seq": 1}}
    (raw / "capture-context.json").write_text(json.dumps(context))
    source = raw / "mihomo-trace.jsonl"
    original = b'{}\n{"type":"tcp_proxy_dial"}\n'
    source.write_bytes(original + b'{"partial":')
    trace = prepare_analysis_trace(raw)
    assert trace.read_bytes() == original
    assert (trace.parent / "capture-context.json").exists()
    source.write_bytes(original + b'{"later":true}\n')
    assert prepare_analysis_trace(raw).read_bytes() == original
    assert source.exists()  # Retention-off is not permission to delete a live source.
    trace.write_bytes(b"tampered\n")
    with pytest.raises(ValueError, match="integrity"):
        analysis_trace_path(raw)


def test_legacy_analysis_does_not_create_snapshot(tmp_path):
    (tmp_path / "capture-context.json").write_text("{}")
    source = tmp_path / "mihomo-trace.jsonl"
    source.write_bytes(b"{}\n")
    assert prepare_analysis_trace(tmp_path) == source
    assert not (tmp_path / "trace-input").exists()


def _snapshot_capture(raw):
    (raw / "capture-context.json").write_text(json.dumps({
        "trace_policy": {"immutable_analysis_input": True},
        "trace_boundary": {"byte_size": 3},
    }))
    (raw / "mihomo-trace.jsonl").write_bytes(b"{}\n")


@pytest.mark.parametrize("member", ["trace.jsonl", "capture-context.json", "snapshot.json"])
def test_resume_rejects_missing_snapshot_member(tmp_path, member):
    _snapshot_capture(tmp_path)
    prepare_analysis_trace(tmp_path)
    (tmp_path / "trace-input" / member).unlink()
    with pytest.raises(ValueError):
        prepare_analysis_trace(tmp_path)


def test_dangling_bundle_symlink_never_falls_back_to_live_input(tmp_path):
    _snapshot_capture(tmp_path)
    (tmp_path / "trace-input").symlink_to(tmp_path / "absent", target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        prepare_analysis_trace(tmp_path)


def test_snapshot_policy_requires_source(tmp_path):
    _snapshot_capture(tmp_path)
    (tmp_path / "mihomo-trace.jsonl").unlink()
    with pytest.raises(ValueError, match="requires"):
        prepare_analysis_trace(tmp_path)


def test_failed_publication_cleans_only_owned_staging(tmp_path, monkeypatch):
    from traffictracer.capture import trace_snapshot
    _snapshot_capture(tmp_path)
    stale = tmp_path / ".trace-input-from-interrupted-process"
    stale.mkdir()
    def fail_sync(_):
        raise OSError("simulated disk failure")
    monkeypatch.setattr(trace_snapshot, "_sync_directory", fail_sync)
    with pytest.raises(OSError, match="disk failure"):
        prepare_analysis_trace(tmp_path)
    assert not (tmp_path / "trace-input").exists()
    assert list(tmp_path.glob(".trace-input-*")) == [stale]
    assert (tmp_path / "mihomo-trace.jsonl").read_bytes() == b"{}\n"


def test_resume_rejects_invalid_metadata(tmp_path):
    _snapshot_capture(tmp_path)
    prepare_analysis_trace(tmp_path)
    (tmp_path / "trace-input/snapshot.json").write_text("[]")
    with pytest.raises(ValueError, match="metadata"):
        prepare_analysis_trace(tmp_path)


def test_copy_cancellation_does_not_publish_or_remove_source(tmp_path):
    source = tmp_path / "live"
    destination = tmp_path / "snapshot"
    source.write_bytes(b"{}\n")
    def cancel():
        raise RuntimeError("cancelled")
    with pytest.raises(RuntimeError, match="cancelled"):
        publish_trace_snapshot(source, destination, 3, checkpoint=cancel)
    assert not destination.exists()
    assert not list(tmp_path.glob(".trace-snapshot-*"))
    assert source.read_bytes() == b"{}\n"
