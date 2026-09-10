import hashlib
import json
import pytest

from traffictracer.capture.trace_snapshot import publish_trace_snapshot
from traffictracer.capture.trace_snapshot import prepare_analysis_trace, analysis_trace_path, open_trace
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
    with open_trace(trace, "rb") as stream:
        assert stream.read() == original
    assert (trace.parent / "capture-context.json").exists()
    source.write_bytes(original + b'{"later":true}\n')
    with open_trace(prepare_analysis_trace(raw), "rb") as stream:
        assert stream.read() == original
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


@pytest.mark.parametrize("member", ["trace.jsonl.gz", "capture-context.json", "snapshot.json"])
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


def test_compressed_snapshot_records_logical_and_stored_hashes(tmp_path):
    import gzip
    _snapshot_capture(tmp_path)
    source = tmp_path / "mihomo-trace.jsonl"
    data = b'{"event_seq":1,"type":"tcp_close"}\n' * 10000
    source.write_bytes(data)
    path = prepare_analysis_trace(tmp_path)
    metadata = json.loads((path.parent / "snapshot.json").read_text())
    assert path.name == "trace.jsonl.gz"
    assert gzip.decompress(path.read_bytes()) == data
    assert metadata["size_bytes"] == len(data)
    assert metadata["stored_size_bytes"] == path.stat().st_size < len(data) / 10
    assert metadata["stored_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert not (path.parent / "trace.jsonl").exists()


def test_legacy_uncompressed_bundle_is_reused_without_migration(tmp_path):
    _snapshot_capture(tmp_path)
    bundle = tmp_path / "trace-input"
    bundle.mkdir()
    context = (tmp_path / "capture-context.json").read_bytes()
    (bundle / "capture-context.json").write_bytes(context)
    trace = bundle / "trace.jsonl"
    trace.write_bytes(b"{}\n")
    (bundle / "snapshot.json").write_text(json.dumps({
        "schema_version": 1, "path": "trace.jsonl", "size_bytes": 3,
        "sha256": hashlib.sha256(b"{}\n").hexdigest(),
        "context_sha256": hashlib.sha256(context).hexdigest(),
    }))
    assert prepare_analysis_trace(tmp_path) == trace
    assert not (bundle / "trace.jsonl.gz").exists()


def test_validation_cache_is_scoped_and_invalidated_by_changes(tmp_path, monkeypatch):
    from traffictracer.capture import trace_snapshot as module
    _snapshot_capture(tmp_path)
    trace = prepare_analysis_trace(tmp_path)
    real_open = module.open_trace
    calls = []
    def tracked(*args, **kwargs):
        calls.append(args)
        return real_open(*args, **kwargs)
    monkeypatch.setattr(module, "open_trace", tracked)
    with module.trace_validation_scope():
        analysis_trace_path(tmp_path)
        analysis_trace_path(tmp_path)
        assert len(calls) == 1
    analysis_trace_path(tmp_path)
    assert len(calls) == 2
    with module.trace_validation_scope():
        analysis_trace_path(tmp_path)
        trace.write_bytes(b"broken")
        with pytest.raises(ValueError, match="integrity"):
            analysis_trace_path(tmp_path)


def test_truncated_gzip_is_rejected_even_with_matching_stored_hash(tmp_path):
    _snapshot_capture(tmp_path)
    trace = prepare_analysis_trace(tmp_path)
    trace.write_bytes(trace.read_bytes()[:-5])
    metadata_path = trace.parent / "snapshot.json"
    meta = json.loads(metadata_path.read_text())
    meta.update(stored_size_bytes=trace.stat().st_size,
                stored_sha256=hashlib.sha256(trace.read_bytes()).hexdigest())
    metadata_path.write_text(json.dumps(meta))
    with pytest.raises((EOFError, ValueError, OSError)):
        analysis_trace_path(tmp_path)


def test_compressed_and_plain_trace_have_identical_analysis_semantics(tmp_path):
    import gzip
    from traffictracer.analyze.mihomo_log import trace_snapshot_info, observed_proxy_protocols
    data = (b'{"type":"tcp_proxy_dial","event_seq":1,"proxy_type":"Shadowsocks"}\n'
            b'{"type":"tcp_close","event_seq":2}\n')
    plain, zipped = tmp_path / "plain.jsonl", tmp_path / "plain.jsonl.gz"
    plain.write_bytes(data)
    zipped.write_bytes(gzip.compress(data))
    assert trace_snapshot_info(str(plain)) == trace_snapshot_info(str(zipped))
    assert observed_proxy_protocols(str(plain)) == observed_proxy_protocols(str(zipped))
