"""Tests for crash-safe atomic Session artifact persistence."""

import json
import os
from pathlib import Path

import pytest

import traffictracer.session.atomic as atomic
from traffictracer.session.atomic import write_json_atomic


def test_atomic_json_writes_complete_deterministic_document(tmp_path):
    destination = tmp_path / "manifest.json"
    write_json_atomic(destination, {"z": 1, "message": "流量", "a": [1, 2]})
    assert json.loads(destination.read_text(encoding="utf-8")) == {
        "a": [1, 2],
        "message": "流量",
        "z": 1,
    }
    assert destination.read_text(encoding="utf-8").endswith("\n")
    assert destination.stat().st_mode & 0o777 == 0o600
    assert not list(tmp_path.glob(".manifest.json.*.tmp"))


def test_replace_failure_preserves_old_file_and_removes_temporary(tmp_path, monkeypatch):
    destination = tmp_path / "manifest.json"
    destination.write_text('{"state":"old"}\n', encoding="utf-8")

    def fail_replace(source, target):
        assert Path(source).parent == destination.parent
        assert Path(target) == destination
        raise OSError("simulated replace failure")

    monkeypatch.setattr(atomic.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated replace failure"):
        write_json_atomic(destination, {"state": "new"})
    assert destination.read_text(encoding="utf-8") == '{"state":"old"}\n'
    assert not list(tmp_path.glob(".manifest.json.*.tmp"))


def test_serialization_failure_preserves_old_file(tmp_path):
    destination = tmp_path / "correlation.json"
    destination.write_text('{"complete":true}\n', encoding="utf-8")
    with pytest.raises(TypeError):
        write_json_atomic(destination, {"invalid": object()})
    assert destination.read_text(encoding="utf-8") == '{"complete":true}\n'
    assert not list(tmp_path.glob(".correlation.json.*.tmp"))


def test_file_fsync_happens_before_replace_and_directory_fsync(tmp_path, monkeypatch):
    destination = tmp_path / "manifest.json"
    events = []
    real_replace = os.replace

    def record_fsync(descriptor):
        kind = "directory" if os.fstat(descriptor).st_mode & 0o40000 else "file"
        events.append(f"fsync:{kind}")

    def record_replace(source, target):
        events.append("replace")
        real_replace(source, target)

    monkeypatch.setattr(atomic.os, "fsync", record_fsync)
    monkeypatch.setattr(atomic.os, "replace", record_replace)
    write_json_atomic(destination, {"state": "created"})
    assert events == ["fsync:file", "replace", "fsync:directory"]


def test_missing_parent_and_invalid_mode_are_rejected(tmp_path):
    with pytest.raises(FileNotFoundError, match="does not exist"):
        write_json_atomic(tmp_path / "missing" / "manifest.json", {})
    with pytest.raises(ValueError, match="mode"):
        write_json_atomic(tmp_path / "manifest.json", {}, mode=0o1000)
