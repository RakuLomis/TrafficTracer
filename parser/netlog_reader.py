"""Incremental NetLog JSON reader using the standard JSON decoder.

Only one event is decoded at a time. The source graph still grows with the
number of events; this removes the redundant raw event tree, not that graph.
"""

from contextlib import contextmanager, ExitStack
import json


class _Reader:
    def __init__(self, stream, checkpoint, chunk_size=65536):
        self.stream, self.checkpoint, self.chunk_size = stream, checkpoint, chunk_size
        self.buffer = ""
        self.pos = 0
        self.eof = False
        self.decoder = json.JSONDecoder()

    def more(self):
        self.checkpoint()
        self.buffer = self.buffer[self.pos:]
        self.pos = 0
        chunk = self.stream.read(self.chunk_size)
        self.eof = not chunk
        self.buffer += chunk
        # Fail explicitly rather than growing without limit on an unterminated
        # string or an exceptionally large individual event/metadata object.
        if len(self.buffer) > 64 * 1024 * 1024:
            raise ValueError("NETLOG_VALUE_TOO_LARGE: individual JSON value exceeds 64 MiB")

    def peek(self):
        while True:
            while self.pos < len(self.buffer) and self.buffer[self.pos] in " \r\n\t":
                self.pos += 1
            if self.pos < len(self.buffer):
                return self.buffer[self.pos]
            if self.eof:
                return ""
            self.more()

    def expect(self, char):
        if self.peek() != char:
            raise json.JSONDecodeError(f"expected {char!r}", self.buffer, self.pos)
        self.pos += 1

    def value(self):
        self.peek()
        while True:
            try:
                value, end = self.decoder.raw_decode(self.buffer, self.pos)
            except json.JSONDecodeError:
                if self.eof:
                    raise
                self.more()
                continue
            # A scalar at a chunk boundary might be a partial number.
            if end == len(self.buffer) and not self.eof:
                self.more()
                continue
            if isinstance(value, (int, float)) and not self.eof and self.buffer[end:end + 1] in ('e', 'E', '.', '+', '-'):
                self.more()
                continue
            self.pos = end
            return value

    def items(self):
        self.expect("{")
        seen = set()
        if self.peek() == "}":
            self.pos += 1
        else:
            while True:
                key = self.value()
                if not isinstance(key, str):
                    raise ValueError("NetLog root keys must be strings")
                if key in seen:
                    raise ValueError("duplicate NetLog root key")
                seen.add(key)
                self.expect(":")
                if key == "events" and self.peek() == "[":
                    self.pos += 1
                    if self.peek() != "]":
                        while True:
                            yield "event", self.value()
                            if self.peek() == "]":
                                break
                            self.expect(",")
                    self.expect("]")
                else:
                    value = self.value()
                    if key == "events" and value not in (None, []):
                        raise ValueError("NetLog events must be an array")
                    yield key, value
                if self.peek() == "}":
                    self.pos += 1
                    break
                self.expect(",")
        if self.peek():
            raise json.JSONDecodeError("extra data", self.buffer, self.pos)


@contextmanager
def open_netlog(path, checkpoint=lambda: None):
    """Yield (constants, event iterator), closing the file even on cancellation.

Chrome writes constants first. Unusual dumps with events first are scanned
once to find constants, then reopened; they never require a full raw JSON tree.
    """
    with ExitStack() as stack:
        stream = path if hasattr(path, "read") else stack.enter_context(open(path, encoding="utf-8"))
        items = _Reader(stream, checkpoint).items()
        constants = {}
        rewind = False
        for key, value in items:
            if key == "constants":
                constants = value or {}
                break
            if key == "event":
                rewind = True
        if rewind:
            stream.seek(0)
            items = _Reader(stream, checkpoint).items()

        def events():
            for key, value in items:
                if key == "event":
                    if not isinstance(value, dict):
                        raise ValueError("NetLog events must be objects")
                    yield value
                elif key == "constants" and value != constants:
                    raise ValueError("NetLog contains conflicting constants")
                elif key == "events" and value not in (None, []):
                    raise ValueError("NetLog events must be an array")

        yield constants, events()
