"""Tests for cooperative Complete job cancellation."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from traffictracer.jobs.cancellation import CancellationToken, CancelledError, InterruptedError


def test_checkpoint_is_a_noop_before_cancellation():
    token = CancellationToken()
    assert not token.cancelled
    assert token.reason == ""
    assert token.checkpoint() is None
    assert not token.wait(0)


def test_cancel_is_idempotent_and_preserves_first_reason():
    token = CancellationToken()
    assert token.cancel("user requested stop")
    assert not token.cancel("later reason")
    assert token.cancelled
    assert token.reason == "user requested stop"
    assert token.wait(0)
    with pytest.raises(CancelledError) as caught:
        token.checkpoint()
    assert caught.value.reason == "user requested stop"
    assert str(caught.value) == "user requested stop"


def test_empty_reason_is_normalized():
    token = CancellationToken()
    assert token.cancel("  ")
    assert token.reason == "cancelled"


def test_concurrent_cancel_has_exactly_one_winner_and_consistent_reason():
    token = CancellationToken()
    reasons = [f"caller-{index}" for index in range(32)]
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(token.cancel, reasons))
    assert results.count(True) == 1
    winner = reasons[results.index(True)]
    assert token.reason == winner
    with pytest.raises(CancelledError, match=winner):
        token.checkpoint()


def test_interrupt_is_idempotent_and_cannot_be_overridden_by_cancel():
    token = CancellationToken()
    assert token.interrupt("pause batch")
    assert not token.cancel("terminal stop")
    assert token.cancelled
    assert token.interrupted
    assert token.intent == "interrupt"
    assert token.reason == "pause batch"
    with pytest.raises(InterruptedError, match="pause batch"):
        token.checkpoint()
