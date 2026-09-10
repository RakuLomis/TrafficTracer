"""Tests for managed, cancellable tshark packet capture."""

import io
import signal
import subprocess
import struct
import threading

import pytest

import traffictracer.capture.tshark as tshark
from traffictracer.capture.tshark import (
    PacketCapture,
    PacketCaptureError,
    start_packet_capture,
    stop_packet_capture,
)


class FakeProcess:
    def __init__(self, *, returncode=None, timeout=False):
        self.pid = 123
        self.returncode = returncode
        self.timeout = timeout
        self.signals = []
        self.killed = False

    def poll(self):
        return self.returncode

    def send_signal(self, value):
        self.signals.append(value)

    def wait(self, timeout=None):
        if self.timeout and not self.killed:
            raise subprocess.TimeoutExpired("tshark", timeout)
        if self.returncode is None:
            self.returncode = -15
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


def _capture(process, stderr=b""):
    stream = io.BytesIO(stderr)
    return PacketCapture(process, "Meta", __import__("pathlib").Path("/tmp/tun.pcap"), ("tshark",), stream)


def test_start_rejects_immediate_dumpcap_permission_failure(monkeypatch, tmp_path):
    process = FakeProcess(returncode=1)

    def fake_popen(command, **kwargs):
        kwargs["stderr"].write(b"dumpcap: Permission denied")
        return process

    monkeypatch.setattr(tshark.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(tshark.time, "sleep", lambda value: None)
    with pytest.raises(PacketCaptureError) as caught:
        start_packet_capture("Meta", tmp_path / "tun.pcap")
    assert caught.value.code == "CAPTURE_PERMISSION_DENIED"
    assert caught.value.interface == "Meta"


def test_normal_stop_uses_sigterm_to_flush_capture_tail():
    process = FakeProcess()
    result = stop_packet_capture(_capture(process))
    assert process.signals == [signal.SIGTERM]
    assert not result.killed
    assert result.exit_code == -15


def test_stop_force_kills_after_timeout():
    process = FakeProcess(timeout=True)
    result = stop_packet_capture(_capture(process), timeout=0.01)
    assert process.killed
    assert result.killed
    assert result.exit_code == -9


def test_empty_interface_is_a_structured_error(tmp_path):
    with pytest.raises(PacketCaptureError) as caught:
        start_packet_capture(" ", tmp_path / "tun.pcap", startup_grace=0)
    assert caught.value.code == "CAPTURE_INTERFACE_INVALID"


def _empty_pcapng(endian="<"):
    section = struct.pack(endian + "IIIHHqI", 0x0a0d0d0a, 28, 0x1a2b3c4d, 1, 0, -1, 28)
    interface = struct.pack(endian + "IIHHII", 1, 20, 1, 0, 65535, 20)
    return section + interface


@pytest.mark.parametrize("endian", ["<", ">"])
def test_readiness_requires_complete_interface_not_first_packet(tmp_path, endian):
    path = tmp_path / "quiet.pcap"
    data = _empty_pcapng(endian)
    for count in range(len(data)):
        path.write_bytes(data[:count])
        assert not tshark.capture_header_ready(path)
    path.write_bytes(data)
    assert tshark.capture_header_ready(path)
    assert tshark.capture_output_complete(path)
    path.write_bytes(data[:-4] + b"xxxx")
    assert not tshark.capture_header_ready(path)
    assert not tshark.capture_output_complete(path)


def test_start_waits_for_header_and_records_readiness(monkeypatch, tmp_path):
    process = FakeProcess()
    path = tmp_path / "quiet.pcap"
    monkeypatch.setattr(tshark.subprocess, "Popen", lambda *a, **kw: process)
    monkeypatch.setattr(tshark.time, "sleep", lambda _: path.write_bytes(_empty_pcapng()))
    capture = start_packet_capture("lo", path)
    assert capture.ready_monotonic > 0
    stop_packet_capture(capture)


def test_unready_capture_times_out_and_is_cleaned_up(monkeypatch, tmp_path):
    process = FakeProcess()
    monkeypatch.setattr(tshark.subprocess, "Popen", lambda *a, **kw: process)
    with pytest.raises(PacketCaptureError, match="CAPTURE_READY_TIMEOUT"):
        start_packet_capture("lo", tmp_path / "quiet.pcap", startup_timeout=.01)
    assert process.returncode is not None


def test_start_cancellation_cleans_unregistered_process(monkeypatch, tmp_path):
    process = FakeProcess()
    monkeypatch.setattr(tshark.subprocess, "Popen", lambda *a, **kw: process)
    def cancel():
        raise RuntimeError("cancelled")
    with pytest.raises(RuntimeError, match="cancelled"):
        start_packet_capture("lo", tmp_path / "quiet.pcap", checkpoint=cancel)
    assert process.returncode is not None


def test_monitor_detects_mid_capture_exit_without_cancelling_parent():
    from traffictracer.jobs.cancellation import CancellationToken
    parent = CancellationToken()
    capture = _capture(FakeProcess())
    monitor = tshark.CaptureMonitor([capture], parent)
    monitor.start()
    try:
        capture.process.returncode = 1
        with pytest.raises(PacketCaptureError, match="CAPTURE_PROCESS_EXITED"):
            monitor.wait(10)
        assert not parent.cancelled
    finally:
        monitor.stop()
        capture.stderr_file.close()
    assert not any(t.name == "capture-health" for t in threading.enumerate())
