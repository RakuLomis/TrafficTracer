"""Tests for the final Chrome cleanup barrier."""

import pytest

from traffictracer.capture.quiescence import (
    ChromeCleanupIncomplete,
    verify_chrome_quiescence,
)


class FakeProcess:
    pid = 123

    def __init__(self, states):
        self.states = list(states)

    def poll(self):
        if len(self.states) > 1:
            return self.states.pop(0)
        return self.states[0]


def test_barrier_accepts_normal_and_delayed_exit():
    clock = [0.0]
    report = verify_chrome_quiescence(
        FakeProcess([None, None, 0]),
        "/tmp/profile",
        timeout=1,
        poll_interval=0.1,
        monotonic=lambda: clock[0],
        sleep=lambda value: clock.__setitem__(0, clock[0] + value),
    )
    assert report.remaining_pids == ()


def test_barrier_reports_stubborn_process_with_stable_error_code():
    clock = [0.0]
    with pytest.raises(ChromeCleanupIncomplete) as raised:
        verify_chrome_quiescence(
            FakeProcess([None]),
            "/tmp/profile",
            timeout=0.2,
            poll_interval=0.1,
            monotonic=lambda: clock[0],
            sleep=lambda value: clock.__setitem__(0, clock[0] + value),
        )
    assert raised.value.code == "CHROME_CLEANUP_INCOMPLETE"
    assert raised.value.report.remaining_pids == (123,)
