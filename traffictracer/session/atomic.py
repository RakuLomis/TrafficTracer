"""Crash-safe atomic JSON persistence for Complete Session artifacts."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any


def write_json_atomic(
    path: str | Path,
    payload: Any,
    *,
    mode: int = 0o600,
    indent: int | None = 2,
) -> None:
    """Write JSON without exposing a partially written destination file."""
    destination = Path(path)
    parent = destination.parent
    if not parent.is_dir():
        raise FileNotFoundError(f"destination directory does not exist: {parent}")
    if not 0 <= mode <= 0o777:
        raise ValueError("mode must be a Unix permission value between 0 and 0o777")

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            os.fchmod(stream.fileno(), mode)
            json.dump(
                payload,
                stream,
                ensure_ascii=False,
                indent=indent,
                sort_keys=True,
                separators=(",", ":") if indent is None else None,
            )
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, destination)
        temporary_path = None
        _fsync_directory(parent)
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return
    try:
        try:
            os.fsync(descriptor)
        except OSError:
            # Some filesystems/platforms allow opening directories but do not
            # implement directory fsync. The file itself is already durable.
            pass
    finally:
        os.close(descriptor)
