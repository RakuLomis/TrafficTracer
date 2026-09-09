import io
import json
from pathlib import Path
import shutil
import struct
import subprocess

import pytest

from parser.netlog_reader import _Reader, open_netlog


@pytest.mark.parametrize("chunk", [1, 7, 65536])
def test_stream_tokens_across_boundaries(chunk):
    data = {"constants": {"unicode": "测试\\\""}, "events": [{"source": {"id": i}, "time": 1.23e12} for i in range(7)]}
    items = list(_Reader(io.StringIO(json.dumps(data)), lambda: None, chunk).items())
    assert items == [("constants", data["constants"])] + [("event", event) for event in data["events"]]
    assert list(_Reader(io.StringIO('{"metadata":1.23e12,"events":[]}'), lambda: None, chunk).items()) == [("metadata", 1.23e12)]


@pytest.mark.parametrize("constants_first", [True, False])
def test_stream_constants_order(tmp_path, constants_first):
    constants = {"logFormatVersion": 1}
    events = [{"source": {"id": 1}}]
    data = dict(constants=constants, events=events) if constants_first else dict(events=events, constants=constants)
    path = tmp_path / "netlog.json"
    path.write_text(json.dumps(data))
    with open_netlog(path) as (actual, iterator):
        assert actual == constants
        assert list(iterator) == events


@pytest.mark.parametrize("data", ['{"constants":{},"events":[{}', '{"constants":{},"events":[{},]}', '{"events":[]} garbage'])
def test_stream_rejects_incomplete_or_extra_input(tmp_path, data):
    path = tmp_path / "netlog.json"
    path.write_text(data)
    with pytest.raises(json.JSONDecodeError):
        with open_netlog(path) as (_, events):
            list(events)


def test_repair_large_whitespace_tail_and_keep_original(tmp_path):
    from traffictracer.analyze.pipeline import _fix_netlog
    path = tmp_path / "netlog.json"
    original = b'{"constants":{},"events":[{"source":{"id":1}},' + b' ' * 70000
    path.write_bytes(original)
    repaired = Path(_fix_netlog(str(path)))
    try:
        assert json.loads(repaired.read_text())["events"] == [{"source": {"id": 1}}]
        assert path.read_bytes() == original
    finally:
        repaired.unlink()


def _udp_pcap(path, pcapng=False):
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records = []
    for index, port in enumerate([443, 53, 443, 80]):
        ethernet = bytes.fromhex("00112233445566778899aabb0800")
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 32, index, 0, 64, 17, 0, b'\x01\x02\x03\x04', b'\x05\x06\x07\x08')
        packet = ethernet + ip + struct.pack("!HHHH", 12345, port, 12, 0) + b'test'
        records.append(struct.pack("<IIII", 1700000000 + index, 123456, len(packet), len(packet)) + packet)
    path.write_bytes(header + b''.join(records))
    if pcapng:
        def block(kind, body):
            size = len(body) + 12
            return struct.pack('<II', kind, size) + body + struct.pack('<I', size)
        section = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        interface = block(1, struct.pack('<HHI', 1, 0, 65535) + struct.pack('<HH', 9, 1) + b'\x09\0\0\0' + b'\0' * 4)
        packets = []
        for index, record in enumerate(records):
            payload = record[16:]
            original = len(payload)
            if index == 2:
                payload = payload[:-2]  # exercise a truncated capture
            timestamp = (1700000000 + index) * 1000000000 + 123456789
            body = struct.pack('<IIIII', index % 2, timestamp >> 32, timestamp & 0xffffffff, len(payload), original)
            packets.append(block(6, body + payload + b'\0' * (-len(payload) % 4)))
        path.write_bytes(section + interface * 2 + b''.join(packets))


@pytest.mark.skipif(shutil.which("tshark") is None, reason="requires tshark")
@pytest.mark.parametrize("pcapng", [False, True])
def test_batched_selection_matches_tshark_packet_bytes_and_times(tmp_path, pcapng):
    from traffictracer.analyze.pcap_batch import BatchExtraction
    source = tmp_path / "source.pcap"
    _udp_pcap(source, pcapng)
    filters = ["udp.dstport == 443", "udp", "tcp"]
    with BatchExtraction() as batch:
        batch.prepare(str(source), filters)
        assert len(batch.cache) == 3, "Lua dispatch must complete on the release baseline"
        for index, expression in enumerate(filters):
            path, metrics = batch.cache[(str(source), expression)]
            if not metrics[0]:
                assert expression == "tcp"
                continue
            expected = tmp_path / f"expected-{index}.pcapng"
            subprocess.run(["tshark", "-r", str(source), "-Y", expression, "-w", str(expected)], check=True, capture_output=True)
            def packets(p):
                raw = subprocess.check_output(["tshark", "-r", str(p), "-T", "jsonraw"], stderr=subprocess.DEVNULL)
                return [packet["_source"]["layers"]["frame_raw"][0] for packet in json.loads(raw)]
            def times(p):
                return subprocess.check_output(["tshark", "-r", str(p), "-T", "fields", "-e", "frame.time_epoch", "-e", "frame.len", "-e", "frame.cap_len"], stderr=subprocess.DEVNULL)
            assert packets(path) == packets(expected)
            assert times(path) == times(expected)


def test_batch_without_completion_marker_falls_back(tmp_path, monkeypatch):
    from traffictracer.analyze import pcap_batch
    source = tmp_path / "source.pcap"
    _udp_pcap(source)
    monkeypatch.setattr(pcap_batch, "run_analysis_command", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "", "Lua unavailable"))
    with pcap_batch.BatchExtraction() as batch:
        batch.prepare(str(source), ["udp", "tcp"])
        assert batch.cache == {}


@pytest.mark.parametrize("data", ['{"events":{},"constants":{}}', '{"events":[],"events":[]}'])
def test_stream_rejects_invalid_shape_and_duplicate_root_keys(tmp_path, data):
    path = tmp_path / "netlog.json"
    path.write_text(data)
    with pytest.raises(ValueError):
        with open_netlog(path) as (_, events):
            list(events)


def test_legacy_zip_reader_matches_plain_file(tmp_path):
    import zipfile
    from parser.domain_analyzer import get_domain_connections
    plain = tmp_path / "netlog.json"
    plain.write_text('{"constants":{},"events":[]}')
    archive = tmp_path / "netlog.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as stream:
        stream.write(plain, "netlog.json")
    assert get_domain_connections(str(archive), "example.com") == get_domain_connections(str(plain), "example.com")
