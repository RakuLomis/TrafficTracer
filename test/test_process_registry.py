"""Tests for job-scoped child process cleanup."""

import subprocess

import pytest

from traffictracer.jobs.process_registry import ProcessRegistry


class FakeProcess:
    def __init__(self, pid, events, *, returncode=None, times_out=False):
        self.pid = pid
        self.events = events
        self.returncode = returncode
        self.times_out = times_out
        self.terminated = False
        self.killed = False

    def poll(self):
        self.events.append((self.pid, "poll"))
        return self.returncode

    def terminate(self):
        self.events.append((self.pid, "terminate"))
        self.terminated = True

    def kill(self):
        self.events.append((self.pid, "kill"))
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        self.events.append((self.pid, "wait", timeout))
        if self.times_out and not self.killed:
            raise subprocess.TimeoutExpired(str(self.pid), timeout)
        if self.returncode is None:
            self.returncode = -15 if self.terminated else 0
        return self.returncode


def test_cleanup_terminates_processes_in_reverse_registration_order():
    events = []
    registry = ProcessRegistry()
    chrome = FakeProcess(101, events)
    tshark = FakeProcess(102, events)
    registry.register(chrome, "chrome")
    registry.register(tshark, "tshark")

    report = registry.cleanup(grace_period=0.25)
    assert report.terminated == ("tshark", "chrome")
    assert report.killed == ()
    assert [event for event in events if event[1] == "terminate"] == [
        (102, "terminate"),
        (101, "terminate"),
    ]
    assert registry.closed


def test_cleanup_kills_a_process_after_timeout():
    events = []
    registry = ProcessRegistry()
    process = FakeProcess(201, events, times_out=True)
    registry.register(process, "dumpcap")

    report = registry.cleanup(grace_period=0.01)
    assert report.terminated == ("dumpcap",)
    assert report.killed == ("dumpcap",)
    assert process.killed
    assert [event[1] for event in events] == ["poll", "terminate", "wait", "kill", "wait"]


def test_cleanup_skips_already_exited_processes():
    events = []
    registry = ProcessRegistry()
    process = FakeProcess(301, events, returncode=0)
    registry.register(process, "finished")

    report = registry.cleanup()
    assert report.already_exited == ("finished",)
    assert report.terminated == ()
    assert events == [(301, "poll")]


def test_cleanup_is_idempotent_and_rejects_late_registration():
    events = []
    registry = ProcessRegistry()
    registry.register(FakeProcess(401, events), "worker-child")
    first = registry.cleanup()
    second = registry.cleanup()
    assert second is first
    assert [event for event in events if event[1] == "terminate"] == [(401, "terminate")]
    with pytest.raises(RuntimeError, match="after cleanup"):
        registry.register(FakeProcess(402, events), "late")


def test_registration_validates_role_pid_and_duplicates():
    events = []
    registry = ProcessRegistry()
    process = FakeProcess(501, events)
    record = registry.register(process, " chrome ")
    assert record.role == "chrome"
    assert record.pid == 501
    assert record.started_at.tzinfo is not None
    assert registry.snapshot() == (record,)
    with pytest.raises(ValueError, match="already registered"):
        registry.register(process, "chrome-again")
    with pytest.raises(ValueError, match="role"):
        registry.register(FakeProcess(502, events), " ")
    with pytest.raises(ValueError, match="PID"):
        registry.register(FakeProcess(0, events), "invalid")
