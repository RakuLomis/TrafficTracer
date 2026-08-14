"""Tests for bounded YouTube playback observation."""

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.capture.playback import (
    observe_youtube_playback,
    youtube_observation_expression,
)
from traffictracer.playback import PlaybackPolicy


def test_youtube_expression_only_switches_internal_click_flag():
    disabled = youtube_observation_expression(False)
    enabled = youtube_observation_expression(True)
    assert "__ALLOW_CLICK__" not in disabled
    assert "__ALLOW_CLICK__" not in enabled
    assert "if (false && adShowing" in disabled
    assert "if (true && adShowing" in enabled
    assert "desired_primary_seconds" not in enabled


def test_fixed_window_keeps_ad_and_primary_durations():
    async def scenario():
        now = [0.0]
        observations = [
            {
                "video_present": False,
                "ad_showing": False,
                "video_paused": True,
                "video_ready_state": 0,
                "video_current_time": 0,
            },
            {
                "video_present": True,
                "ad_showing": True,
                "skip_clicked": True,
                "video_paused": False,
                "video_ready_state": 4,
                "video_current_time": 1,
            },
            {
                "video_present": True,
                "ad_showing": False,
                "video_paused": False,
                "video_ready_state": 4,
                "video_current_time": 0,
            },
            {
                "video_present": True,
                "ad_showing": False,
                "video_paused": False,
                "video_ready_state": 4,
                "video_current_time": 0.5,
            },
            {
                "video_present": True,
                "ad_showing": False,
                "video_paused": False,
                "video_ready_state": 4,
                "video_current_time": 1.0,
            },
            {
                "video_present": True,
                "ad_showing": False,
                "video_paused": False,
                "video_ready_state": 4,
                "video_current_time": 1.5,
            },
        ]

        async def evaluate(allow_click):
            index = min(int(now[0] / 0.5), len(observations) - 1)
            result = dict(observations[index])
            if result.get("skip_clicked"):
                result["skip_clicked"] = allow_click
            now[0] += 0.5
            return result

        progress = []
        return await observe_youtube_playback(
            PlaybackPolicy("youtube", desired_primary_seconds=1),
            3,
            evaluate=evaluate,
            started_at=0,
            clock=lambda: now[0],
            checkpoint=lambda: None,
            progress=progress.append,
            poll_interval=0,
        ), progress

    result, progress = asyncio.run(scenario())
    assert result["observed_total_seconds"] == 3
    assert result["phase_seconds"]["advertisement"] > 0
    assert result["phase_seconds"]["primary_content"] >= 1
    assert result["skip_attempts"] == 1
    assert result["primary_goal_met"] is True
    assert result["quality"] == "good"
    assert progress[-1]["elapsed_seconds"] == 3


def test_observation_failure_is_quality_unknown_not_capture_error():
    async def scenario():
        now = [0.0]

        async def evaluate(_allow_click):
            now[0] += 0.5
            raise RuntimeError("page context unavailable")

        return await observe_youtube_playback(
            PlaybackPolicy("youtube", desired_primary_seconds=1),
            1,
            evaluate=evaluate,
            started_at=0,
            clock=lambda: now[0],
            checkpoint=lambda: None,
            poll_interval=0,
        )

    result = asyncio.run(scenario())
    assert result["primary_goal_met"] is False
    assert result["quality"] == "unknown"
    assert result["reason"] == "PLAYBACK_STATE_UNKNOWN"
    assert result["automation_available"] is False
    assert result["evaluation_errors"] == 2
