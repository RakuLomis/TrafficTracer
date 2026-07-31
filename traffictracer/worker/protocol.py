"""Robust UTF-8 JSONL framing for the Complete Worker stdio protocol."""

from __future__ import annotations

from dataclasses import dataclass
import json
from threading import Lock
from typing import Any, BinaryIO, Iterator

from traffictracer.contracts import validate_worker_message
from traffictracer.version import WORKER_API_VERSION


DEFAULT_MAX_MESSAGE_BYTES = 1024 * 1024


@dataclass(frozen=True)
class ProtocolFailure:
    reason: str
    message: str

    def to_response(self) -> dict[str, Any]:
        return {
            "api_version": WORKER_API_VERSION,
            "type": "response",
            "id": None,
            "error": {
                "code": "INVALID_REQUEST",
                "message": self.message,
                "data": {"reason": self.reason},
            },
        }


Frame = dict[str, Any] | ProtocolFailure


class JsonlDecoder:
    """Incrementally decode arbitrarily fragmented byte chunks into JSON objects."""

    def __init__(self, max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES) -> None:
        if max_message_bytes < 64:
            raise ValueError("max_message_bytes must be at least 64")
        self.max_message_bytes = max_message_bytes
        self._buffer = bytearray()
        self._discarding_oversized = False
        self._finished = False

    def feed(self, chunk: bytes) -> list[Frame]:
        if self._finished:
            raise RuntimeError("cannot feed a finished JSONL decoder")
        if not isinstance(chunk, bytes):
            raise TypeError("JSONL decoder accepts bytes")
        frames: list[Frame] = []
        cursor = 0
        while cursor < len(chunk):
            newline = chunk.find(b"\n", cursor)
            end = len(chunk) if newline < 0 else newline
            segment = chunk[cursor:end]
            if self._discarding_oversized:
                if newline < 0:
                    return frames
                self._discarding_oversized = False
            else:
                available = self.max_message_bytes - len(self._buffer)
                if len(segment) > available:
                    self._buffer.clear()
                    frames.append(ProtocolFailure(
                        "MESSAGE_TOO_LARGE",
                        f"JSONL message exceeds {self.max_message_bytes} bytes.",
                    ))
                    if newline < 0:
                        self._discarding_oversized = True
                        return frames
                else:
                    self._buffer.extend(segment)
                    if newline >= 0:
                        frames.append(_decode_line(bytes(self._buffer)))
                        self._buffer.clear()
            if newline < 0:
                break
            cursor = newline + 1
        return frames

    def finish(self) -> list[Frame]:
        if self._finished:
            return []
        self._finished = True
        if self._discarding_oversized or not self._buffer:
            self._buffer.clear()
            return []
        line = bytes(self._buffer)
        self._buffer.clear()
        return [_decode_line(line)]


def read_jsonl(
    stream: BinaryIO,
    *,
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
    chunk_size: int = 8192,
) -> Iterator[Frame]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    decoder = JsonlDecoder(max_message_bytes)
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            yield from decoder.finish()
            return
        yield from decoder.feed(chunk)


class JsonlWriter:
    """Validate and atomically write one protocol object per stdout line."""

    def __init__(
        self,
        stream: BinaryIO,
        *,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
    ) -> None:
        if max_message_bytes < 64:
            raise ValueError("max_message_bytes must be at least 64")
        self._stream = stream
        self._max_message_bytes = max_message_bytes
        self._lock = Lock()

    def write(self, message: dict[str, Any]) -> None:
        validate_worker_message(message)
        encoded = json.dumps(
            message,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(encoded) > self._max_message_bytes:
            raise ValueError(
                f"encoded Worker message exceeds {self._max_message_bytes} bytes"
            )
        with self._lock:
            self._stream.write(encoded + b"\n")
            self._stream.flush()


def _decode_line(raw: bytes) -> Frame:
    if raw.endswith(b"\r"):
        raw = raw[:-1]
    if not raw:
        return ProtocolFailure("EMPTY_MESSAGE", "JSONL message must not be empty.")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return ProtocolFailure(
            "INVALID_UTF8", "JSONL message must be valid UTF-8."
        )
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return ProtocolFailure(
            "INVALID_JSON", "JSONL message must contain one valid JSON object."
        )
    if not isinstance(payload, dict):
        return ProtocolFailure(
            "JSON_OBJECT_REQUIRED", "JSONL message must be a JSON object."
        )
    return payload
