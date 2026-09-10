"""Lossless, nonblocking journal archival after all cooperating writers close.

The immutable analysis input is never changed. The full source, including late
lifecycle events, is gzip archived before its manifest entry can be replaced.
The caller must commit the new manifest before calling remove_original().
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import time
from typing import Callable

from .trace_snapshot import analysis_trace_path, _sync_directory


@dataclass
class RetentionResult:
    state: str
    paths: tuple[Path, ...] = ()
    source: Path | None = None
    identity: tuple[int, int, int, int] | None = None

    def remove_original(self) -> bool:
        """Called only inside the lock scope, after durable manifest commit."""
        if self.source is None or self.identity is None:
            return False
        try:
            if _identity(self.source.stat(follow_symlinks=False)) != self.identity:
                return False
            self.source.unlink()
            _sync_directory(self.source.parent)
            return True
        except OSError:
            # A redundant original is safer than failing a completed analysis.
            return False


def _identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _verify_archive(bundle: Path, checkpoint: Callable[[], None]) -> dict:
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("invalid trace archive bundle")
    meta_path, data_path = bundle / "archive.json", bundle / "journal.jsonl.gz"
    if any(p.is_symlink() or not p.is_file() for p in (meta_path, data_path)):
        raise ValueError("trace archive member unavailable")
    meta = json.loads(meta_path.read_text())
    if (not isinstance(meta, dict) or meta.get("schema_version") != 1
            or type(meta.get("source_size_bytes")) is not int
            or meta["source_size_bytes"] <= 0
            or meta.get("format") != "gzip"
            or meta.get("includes_late_lifecycle_events") is not True):
        raise ValueError("invalid trace archive metadata")
    size, digest = 0, hashlib.sha256()
    with gzip.open(data_path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checkpoint()
            size += len(block)
            if size > meta["source_size_bytes"]:
                raise ValueError("trace archive exceeds recorded size")
            digest.update(block)
    if size != meta["source_size_bytes"] or digest.hexdigest() != meta.get("source_sha256"):
        raise ValueError("trace archive integrity mismatch")
    return meta


def _archive(raw, reader, info, checkpoint):
    snapshot = analysis_trace_path(raw, checkpoint=checkpoint)
    metadata = json.loads((snapshot.parent / "snapshot.json").read_text())
    size = metadata["size_bytes"]
    if size > info.st_size:
        raise ValueError("journal is shorter than analysis input")
    bundle = raw / "trace-archive"
    staging = Path(tempfile.mkdtemp(prefix=".trace-archive-", dir=raw))
    try:
        digest, prefix_digest = hashlib.sha256(), hashlib.sha256()
        consumed = 0
        with (staging / "journal.jsonl.gz").open("wb") as output:
            with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as zipped:
                while consumed < info.st_size:
                    checkpoint()
                    block = reader.read(min(1024 * 1024, info.st_size - consumed))
                    if not block:
                        raise ValueError("journal shrank during archival")
                    digest.update(block)
                    prefix_digest.update(block[:max(0, size - consumed)])
                    zipped.write(block)
                    consumed += len(block)
            output.flush()
            os.fsync(output.fileno())
        if prefix_digest.hexdigest() != metadata["sha256"]:
            raise ValueError("journal no longer contains the analysis input")
        if _identity(os.fstat(reader.fileno())) != _identity(info):
            raise ValueError("journal changed during archival")
        meta = {"schema_version": 1, "source": "../mihomo-trace.jsonl",
                "source_size_bytes": consumed, "source_sha256": digest.hexdigest(),
                "analysis_snapshot_sha256": metadata["sha256"],
                "format": "gzip", "includes_late_lifecycle_events": True}
        with (staging / "archive.json").open("w") as output:
            json.dump(meta, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        _verify_archive(staging, checkpoint)
        _sync_directory(staging)
        if bundle.exists() or bundle.is_symlink():
            existing = _verify_archive(bundle, checkpoint)
            if existing != meta:
                raise ValueError("existing archive is a different journal generation")
        else:
            staging.rename(bundle)
            _sync_directory(raw)
        return bundle
    finally:
        if staging.exists():
            shutil.rmtree(staging)


@contextmanager
def retain_journal(raw: Path, *, checkpoint: Callable[[], None] = lambda: None):
    """One bounded attempt per analysis; pending work is retried on reanalysis.

    Old cores/platforms without the advertised lock contract retain the source.
    There is no polling, writer termination or automatic historical migration.
    """
    context_path = raw / "trace-input/capture-context.json"
    if not context_path.is_file():
        yield RetentionResult("legacy")
        return
    context = json.loads(context_path.read_text())
    if context.get("trace_policy", {}).get("retain_journal", True) is not False:
        yield RetentionResult("retained")
        return
    if sys.platform != "linux" or context.get("trace_boundary", {}).get("journal_locking") is not True:
        yield RetentionResult("pending_unsupported_core")
        return
    import fcntl
    deadline = time.monotonic() + 30.0
    user_checkpoint = checkpoint
    def checkpoint():
        user_checkpoint()
        if time.monotonic() >= deadline:
            raise TimeoutError("journal archive deadline exceeded")
    source = raw / "mihomo-trace.jsonl"
    reader = None
    try:
        try:
            if not source.exists() and not source.is_symlink():
                bundle = raw / "trace-archive"
                archived = _verify_archive(bundle, checkpoint)
                snapshot = analysis_trace_path(raw, checkpoint=checkpoint)
                frozen = json.loads((snapshot.parent / "snapshot.json").read_text())
                if archived.get("analysis_snapshot_sha256") != frozen["sha256"]:
                    raise ValueError("archive belongs to a different analysis input")
                result = RetentionResult("archived", (bundle / "journal.jsonl.gz", bundle / "archive.json"))
            else:
                fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
                reader = os.fdopen(fd, "rb")
                info = os.fstat(reader.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError("journal is not a regular file")
                fcntl.flock(reader.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                bundle = _archive(raw, reader, info, checkpoint)
                result = RetentionResult("archived", (bundle / "journal.jsonl.gz", bundle / "archive.json"),
                                         source, _identity(info))
        except BlockingIOError:
            result = RetentionResult("pending_writer")
        except (OSError, ValueError, EOFError):
            # Optional housekeeping cannot turn valid analysis into failure.
            result = RetentionResult("pending_archive_error")
        yield result
    finally:
        if reader is not None:
            reader.close()
