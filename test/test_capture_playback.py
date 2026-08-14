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
    assert "__ALLOW_PLAY__" not in disabled
    assert "if (false && skipButton)" in disabled
    assert "if (true && skipButton)" in enabled
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

        async def evaluate(allow_click, _allow_play):
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
    assert result["skip_attempts"] == 0
    assert result["primary_goal_met"] is True
    assert result["quality"] == "good"
    assert progress[-1]["elapsed_seconds"] == 3


def test_observation_failure_is_quality_unknown_not_capture_error():
    async def scenario():
        now = [0.0]

        async def evaluate(_allow_click, _allow_play):
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


def test_visible_skip_does_not_require_ad_class_and_player_api_can_confirm_playback():
    expression = youtube_observation_expression(True, True)
    assert "if (true && skipButton)" in expression
    assert "getPlayerState" in expression
    assert "player.playVideo" in expression


def test_interactions_wait_for_initial_five_seconds_and_diagnostics_are_bounded():
    async def scenario():
        now = [0.0]
        interaction_flags = []

        async def evaluate(allow_click, allow_play):
            interaction_flags.append((now[0], allow_click, allow_play))
            now[0] += 0.5
            return {
                "player_present": True,
                "video_present": True,
                "ad_showing": now[0] < 6,
                "skip_visible": now[0] < 6,
                "skip_clicked": allow_click and now[0] < 6,
                "play_requested": allow_play and now[0] >= 6,
                "player_state": 1 if now[0] >= 6 else 2,
                "video_paused": now[0] < 6,
                "video_ready_state": 4,
                "video_current_time": max(0, now[0] - 6),
                "video_candidate_count": 1,
            }

        result = await observe_youtube_playback(
            PlaybackPolicy("youtube", desired_primary_seconds=1),
            8,
            evaluate=evaluate,
            started_at=0,
            clock=lambda: now[0],
            checkpoint=lambda: None,
            poll_interval=0,
        )
        return result, interaction_flags

    result, flags = asyncio.run(scenario())
    assert all(not click and not play for at, click, play in flags if at < 5)
    assert result["skip_attempts"] >= 1
    assert result["primary_goal_met"] is True
    assert result["diagnostics"]["counts"]["samples"] == len(flags)
    assert "video_current_time" not in result["diagnostics"]["last_observation"]
