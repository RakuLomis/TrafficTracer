"""Tests for managed, cancellable tshark packet capture."""

import io
import signal
import subprocess

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
