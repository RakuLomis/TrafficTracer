"""Tests for robust fragmented Worker JSONL framing."""

from io import BytesIO
import json

import pytest

from traffictracer.contracts import ValidationError, validate_worker_message
from traffictracer.worker.protocol import (
    JsonlDecoder,
    JsonlWriter,
    ProtocolFailure,
    read_jsonl,
)


def _request(request_id="one"):
    return {
        "api_version": 2,
        "type": "request",
        "id": request_id,
        "method": "hello",
        "params": {},
    }


def _line(payload):
    return json.dumps(payload, separators=(",", ":")).encode() + b"\n"


def test_fragmented_utf8_json_and_multiple_frames_decode_in_order():
    first = _line(_request("一"))
    second = _line(_request("two"))
    decoder = JsonlDecoder(1024)
    frames = []
    for byte in first + second:
        frames.extend(decoder.feed(bytes([byte])))
    frames.extend(decoder.finish())
    assert frames == [_request("一"), _request("two")]


def test_crlf_and_final_line_without_newline_are_supported():
    data = _line(_request(1)).replace(b"\n", b"\r\n") + _line(_request(2))[:-1]
    assert list(read_jsonl(BytesIO(data), chunk_size=3)) == [_request(1), _request(2)]


def test_bad_json_yields_error_and_next_request_still_decodes():
    frames = list(read_jsonl(BytesIO(b"{bad json}\n" + _line(_request()))))
    assert isinstance(frames[0], ProtocolFailure)
    assert frames[0].reason == "INVALID_JSON"
    assert validate_worker_message(frames[0].to_response())
    assert frames[1] == _request()


def test_non_utf8_yields_error_and_next_request_still_decodes():
    frames = list(read_jsonl(BytesIO(b"\xff\xfe\n" + _line(_request()))))
    assert isinstance(frames[0], ProtocolFailure)
    assert frames[0].reason == "INVALID_UTF8"
    assert frames[1] == _request()


def test_oversized_fragmented_line_is_discarded_once_without_losing_next_frame():
    oversized = b'{"padding":"' + (b"x" * 200) + b'"}\n'
    frames = list(
        read_jsonl(
            BytesIO(oversized + _line(_request("after"))),
            max_message_bytes=100,
            chunk_size=7,
        )
    )
    assert len(frames) == 2
    assert isinstance(frames[0], ProtocolFailure)
    assert frames[0].reason == "MESSAGE_TOO_LARGE"
    assert frames[1] == _request("after")


def test_empty_and_non_object_messages_are_structured_errors():
    frames = list(read_jsonl(BytesIO(b"\n[]\n")))
    assert [frame.reason for frame in frames if isinstance(frame, ProtocolFailure)] == [
        "EMPTY_MESSAGE",
        "JSON_OBJECT_REQUIRED",
    ]


def test_writer_validates_compacts_flushes_and_delimits_stdout_messages():
    stream = BytesIO()
    writer = JsonlWriter(stream)
    response = {
        "api_version": 2,
        "type": "response",
        "id": "one",
        "result": {"status": "ok"},
    }
    writer.write(response)
    assert stream.getvalue().endswith(b"\n")
    assert stream.getvalue().count(b"\n") == 1
    assert json.loads(stream.getvalue()) == response


def test_writer_rejects_invalid_or_oversized_protocol_output():
    with pytest.raises(ValidationError):
        JsonlWriter(BytesIO()).write({"debug": "must go to stderr"})
    writer = JsonlWriter(BytesIO(), max_message_bytes=100)
    response = {
        "api_version": 2,
        "type": "response",
        "id": "one",
        "result": {"padding": "x" * 200},
    }
    with pytest.raises(ValueError, match="exceeds"):
        writer.write(response)
