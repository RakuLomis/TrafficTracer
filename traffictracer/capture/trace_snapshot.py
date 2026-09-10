"""Publish an immutable trace prefix without stopping its append-only source."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import shutil
import tempfile
import time
from typing import Callable


def analysis_trace_path(raw: Path, *, checkpoint: Callable[[], None] = lambda: None) -> Path:
    """Resolve only a committed input bundle; partial bundles are hard errors."""
    bundle = raw / "trace-input"
    if bundle.is_symlink():
        raise ValueError("analysis trace bundle must not be a symlink")
    if not bundle.exists():
        return raw / "mihomo-trace.jsonl"
    metadata_path = bundle / "snapshot.json"
    if metadata_path.is_symlink() or not metadata_path.is_file():
        raise ValueError("analysis trace metadata is unavailable")
    metadata = json.loads(metadata_path.read_text())
    if (not isinstance(metadata, dict) or metadata.get("schema_version") != 1
            or type(metadata.get("size_bytes")) is not int
            or metadata["size_bytes"] <= 0
            or metadata.get("path") != "trace.jsonl"
            or any(not isinstance(metadata.get(key), str) or len(metadata[key]) != 64
                   for key in ("sha256", "context_sha256"))):
        raise ValueError("invalid analysis trace metadata")
    trace = bundle / "trace.jsonl"
    if trace.is_symlink() or not trace.is_file():
        raise ValueError("analysis trace snapshot is unavailable")
    digest = hashlib.sha256()
    with trace.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checkpoint()
            digest.update(block)
    if trace.stat().st_size != metadata["size_bytes"] or digest.hexdigest() != metadata["sha256"]:
        raise ValueError("analysis trace snapshot integrity mismatch")
    context = bundle / "capture-context.json"
    if (context.is_symlink() or not context.is_file()
            or hashlib.sha256(context.read_bytes()).hexdigest() != metadata["context_sha256"]):
        raise ValueError("analysis trace context integrity mismatch")
    return trace


def prepare_analysis_trace(raw: Path, *, checkpoint: Callable[[], None] = lambda: None) -> Path:
    """Freeze new opt-in captures once, including causal tail available at analysis.

    The capture cutoff remains in the copied context. Taking a complete prefix
    at analysis start also preserves the existing parser's causal-tail evidence;
    it does not widen the capture cutoff to include arbitrary background flows.
    Legacy captures without the policy marker are not automatically converted.
    """
    raw = Path(raw)
    bundle = raw / "trace-input"
    if bundle.exists() or bundle.is_symlink():
        return analysis_trace_path(raw, checkpoint=checkpoint)
    source = raw / "mihomo-trace.jsonl"
    context_path = raw / "capture-context.json"
    if not context_path.is_file():
        return source
    context_bytes = context_path.read_bytes()
    context = json.loads(context_bytes)
    if not context.get("trace_policy", {}).get("immutable_analysis_input", False):
        return source
    if source.is_symlink() or not source.is_file():
        raise ValueError("snapshot-enabled capture requires a regular trace journal")
    # Read only the EOF sampled here; discard an incomplete last record from
    # the snapshot, never from the original journal. A record may span chunks.
    with source.open("rb") as stream:
        boundary = os.fstat(stream.fileno()).st_size
        while boundary:
            checkpoint()
            start = max(0, boundary - 1024 * 1024)
            stream.seek(start)
            data = stream.read(boundary - start)
            newline = data.rfind(b"\n")
            if newline >= 0:
                boundary = start + newline + 1
                break
            boundary = start
    minimum = context.get("trace_boundary", {}).get("byte_size", 0)
    if type(minimum) is not int or minimum < 0:
        raise ValueError("invalid capture barrier byte size")
    if boundary < minimum:
        raise ValueError("analysis prefix does not contain the capture barrier")
    staging = Path(tempfile.mkdtemp(prefix=".trace-input-", dir=raw))
    try:
        metadata = publish_trace_snapshot(source, staging / "trace.jsonl", boundary,
                                          checkpoint=checkpoint)
        metadata.update({"schema_version": 1, "path": "trace.jsonl",
                         "source": "../mihomo-trace.jsonl", "boundary_kind": "analysis_start_complete_prefix",
                         "context_sha256": hashlib.sha256(context_bytes).hexdigest()})
        (staging / "capture-context.json").write_bytes(context_bytes)
        (staging / "snapshot.json").write_text(json.dumps(metadata, indent=2) + "\n")
        for path in (staging / "capture-context.json", staging / "snapshot.json"):
            with path.open("rb") as stream:
                os.fsync(stream.fileno())
        _sync_directory(staging)
        try:
            staging.rename(bundle)
        except OSError:
            if not bundle.exists():
                raise
        _sync_directory(raw)
        return analysis_trace_path(raw, checkpoint=checkpoint)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def _sync_directory(path: Path) -> None:
    """Make bundle publication durable on the supported Linux filesystem."""
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_trace_snapshot(source: Path, destination: Path, byte_limit: int,
                           *, timeout: float = 30.0,
                           checkpoint: Callable[[], None] = lambda: None) -> dict:
    """Copy an explicitly confirmed byte boundary, never the changing EOF.

    The caller must obtain byte_limit from a flushed trace boundary. This helper
    neither infers a boundary from file stability nor deletes the live journal.
    Publication is exclusive: an existing generation is never overwritten.
    """
    if type(byte_limit) is not int or byte_limit <= 0:
        raise ValueError("trace snapshot boundary must be a positive integer")
    if timeout <= 0:
        raise ValueError("trace snapshot timeout must be positive")
    deadline = time.monotonic() + timeout
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError("snapshot must not replace its live journal")
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    temporary = None
    try:
        fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as reader:
            initial = os.fstat(reader.fileno())
            if not stat.S_ISREG(initial.st_mode) or initial.st_size < byte_limit:
                raise ValueError("trace journal is not a regular file containing the boundary")
            fd, temporary = tempfile.mkstemp(prefix=".trace-snapshot-", dir=destination.parent)
            with os.fdopen(fd, "wb") as writer:
                remaining = byte_limit
                last = b""
                while remaining:
                    checkpoint()
                    if time.monotonic() >= deadline:
                        raise TimeoutError("trace snapshot copy deadline exceeded")
                    block = reader.read(min(1024 * 1024, remaining))
                    if not block:
                        raise ValueError("trace journal shrank before its confirmed boundary")
                    writer.write(block)
                    digest.update(block)
                    remaining -= len(block)
                    last = block[-1:]
                if last != b"\n":
                    raise ValueError("trace boundary must end at a complete JSONL record")
                writer.flush()
                os.fsync(writer.fileno())
            current = source.stat(follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (initial.st_dev, initial.st_ino):
                raise ValueError("trace journal was replaced during snapshot copy")
            if current.st_size < byte_limit:
                raise ValueError("trace journal shrank during snapshot copy")
        # Same-directory hard link gives exclusive, atomic publication on Linux.
        os.link(temporary, destination)
        return {"size_bytes": byte_limit, "sha256": digest.hexdigest(),
                "source": str(source), "path": str(destination)}
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)
