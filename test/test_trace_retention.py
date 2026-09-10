import fcntl
import gzip
import json
from pathlib import Path

import pytest

from traffictracer.capture.trace_retention import retain_journal
from traffictracer.capture.trace_snapshot import prepare_analysis_trace
from traffictracer.jobs.cancellation import CancelledError


def capture(raw: Path, *, retain=False, locking=True):
    context = {"trace_policy": {"immutable_analysis_input": True, "retain_journal": retain},
               "trace_boundary": {"byte_size": 3, "journal_locking": locking}}
    (raw / "capture-context.json").write_text(json.dumps(context))
    source = raw / "mihomo-trace.jsonl"
    source.write_bytes(b"{}\n")
    prepare_analysis_trace(raw)
    with source.open("ab") as stream:
        stream.write(b'{"type":"tcp_close"}\n')
    return source


def test_lossless_archive_keeps_late_events_and_removes_only_on_commit(tmp_path):
    source = capture(tmp_path)
    original = source.read_bytes()
    with retain_journal(tmp_path) as result:
        assert result.state == "archived"
        assert source.exists()  # Publication alone cannot delete a journal.
        assert gzip.decompress(result.paths[0].read_bytes()) == original
        assert (tmp_path / "trace-input/trace.jsonl").read_bytes() == b"{}\n"
        assert result.remove_original()
    assert not source.exists()
    with retain_journal(tmp_path) as resumed:
        assert resumed.state == "archived"
        assert all(p.is_file() for p in resumed.paths)
    assert prepare_analysis_trace(tmp_path).read_bytes() == b"{}\n"


def test_live_writer_is_not_waited_on_or_deleted(tmp_path):
    source = capture(tmp_path)
    with source.open("ab") as writer:
        fcntl.flock(writer.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
        with retain_journal(tmp_path) as result:
            assert result.state == "pending_writer"
            assert not result.remove_original()
    assert source.exists()
    assert not (tmp_path / "trace-archive").exists()
    with retain_journal(tmp_path) as result:
        assert result.state == "archived"


@pytest.mark.parametrize("retain,locking,state", [(True, True, "retained"),
                                                    (False, False, "pending_unsupported_core")])
def test_default_retention_and_old_cores_never_delete(tmp_path, retain, locking, state):
    source = capture(tmp_path, retain=retain, locking=locking)
    with retain_journal(tmp_path) as result:
        assert result.state == state
        assert not result.remove_original()
    assert source.exists()
    assert not (tmp_path / "trace-archive").exists()


def test_changed_analysis_prefix_cannot_be_archived(tmp_path):
    source = capture(tmp_path)
    source.write_bytes(b"[]\n")
    with retain_journal(tmp_path) as result:
        assert result.state == "pending_archive_error"
        assert not result.remove_original()
    assert source.exists()
    assert not list(tmp_path.glob(".trace-archive-*"))


def test_manifest_failure_keeps_source_and_allows_idempotent_retry(tmp_path):
    source = capture(tmp_path)
    with pytest.raises(RuntimeError, match="manifest"):
        with retain_journal(tmp_path) as result:
            assert result.state == "archived"
            raise RuntimeError("manifest write failed")
    assert source.exists()
    with retain_journal(tmp_path) as result:
        assert result.state == "archived"
        assert result.remove_original()


def test_cancellation_propagates_without_removal(tmp_path):
    source = capture(tmp_path)
    def cancel():
        raise CancelledError("stop")
    with pytest.raises(CancelledError):
        with retain_journal(tmp_path, checkpoint=cancel):
            pytest.fail("cancelled archive was published")
    assert source.exists()
    assert not list(tmp_path.glob(".trace-archive-*"))


def test_corrupt_archive_never_authorizes_removal(tmp_path):
    source = capture(tmp_path)
    with retain_journal(tmp_path):
        pass
    (tmp_path / "trace-archive/journal.jsonl.gz").write_bytes(b"broken")
    with retain_journal(tmp_path) as result:
        assert result.state == "pending_archive_error"
        assert not result.remove_original()
    assert source.exists()
