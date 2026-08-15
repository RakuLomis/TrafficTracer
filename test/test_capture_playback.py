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


RECT = {"center_x": 400, "center_y": 300}


def test_youtube_expression_is_read_only_and_scopes_controls_to_player():
    expression = youtube_observation_expression()
    assert ".video-ads.ytp-ad-module" in expression
    assert ".ytp-skip-ad .ytp-skip-ad-button" in expression
    assert "elementFromPoint" in expression
    assert "skipButton.click" not in expression
    assert "player.playVideo" not in expression
    assert "video.play" not in expression
    assert "querySelectorAll('button, [role=\"button\"]')" not in expression
    assert "desired_primary_seconds" not in expression


def test_fixed_window_keeps_ad_and_advancing_primary_durations():
    async def scenario():
        now = [0.0]
        observations = [
            {
                "video_present": False, "ad_showing": False,
                "video_paused": True, "video_ready_state": 0,
                "video_current_time": 0,
            },
            {
                "video_present": True, "ad_showing": True,
                "skip_visible": True, "skip_enabled": True,
                "skip_rect": RECT, "video_paused": False,
                "video_ready_state": 4, "video_current_time": 1,
            },
            {
                "video_present": True, "ad_showing": False,
                "video_paused": False, "video_ready_state": 4,
                "video_current_time": 0,
            },
            {
                "video_present": True, "ad_showing": False,
                "video_paused": False, "video_ready_state": 4,
                "video_current_time": 0.5,
            },
            {
                "video_present": True, "ad_showing": False,
                "video_paused": False, "video_ready_state": 4,
                "video_current_time": 1.0,
            },
            {
                "video_present": True, "ad_showing": False,
                "video_paused": False, "video_ready_state": 4,
                "video_current_time": 1.5,
            },
        ]

        async def evaluate():
            index = min(int(now[0] / 0.5), len(observations) - 1)
            result = dict(observations[index])
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
    assert result["primary_content_observed"] is True
    assert result["primary_goal_met"] is True
    assert result["quality"] == "good"
    assert result["ad_observed"] is True
    assert progress[-1]["elapsed_seconds"] == 3


def test_observation_failure_is_quality_unknown_not_capture_error():
    async def scenario():
        now = [0.0]

        async def evaluate():
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
    assert result["primary_content_observed"] is False
    assert result["primary_goal_met"] is False
    assert result["quality"] == "unknown"
    assert result["reason"] == "PLAYBACK_STATE_UNKNOWN"
    assert result["automation_available"] is False
    assert result["evaluation_errors"] == 2


def test_skip_uses_bounded_interaction_after_initial_five_seconds():
    async def scenario():
        now = [0.0]
        actions = []

        async def evaluate():
            now[0] += 0.5
            ad = now[0] < 6
            return {
                "player_present": True,
                "video_present": True,
                "ad_showing": ad,
                "skip_visible": ad,
                "skip_enabled": ad,
                "skip_rect": RECT if ad else None,
                "play_visible": False,
                "player_state": 2 if ad else 1,
                "video_paused": ad,
                "video_ready_state": 4,
                "video_current_time": max(0, now[0] - 6),
                "video_candidate_count": 1,
            }

        async def interact(action, rect):
            actions.append((now[0] - 0.5, action, dict(rect)))
            return True

        result = await observe_youtube_playback(
            PlaybackPolicy("youtube", desired_primary_seconds=1),
            8,
            evaluate=evaluate,
            interact=interact,
            started_at=0,
            clock=lambda: now[0],
            checkpoint=lambda: None,
            poll_interval=0,
        )
        return result, actions

    result, actions = asyncio.run(scenario())
    assert actions == [(5.0, "skip", RECT)]
    assert result["skip_attempts"] == 1
    assert result["skip_confirmed"] is True
    assert result["primary_content_observed"] is True
    assert result["primary_goal_met"] is True
    assert result["diagnostics"]["counts"]["samples"] == 16
    assert "video_current_time" not in result["diagnostics"]["last_observation"]


def test_direct_primary_without_ad_is_successful_and_not_a_skip_failure():
    async def scenario():
        now = [0.0]
        playing = [False]
        actions = []

        async def evaluate():
            now[0] += 0.5
            current = max(0, now[0] - 5) if playing[0] else 0
            return {
                "player_present": True,
                "video_present": True,
                "ad_showing": False,
                "skip_visible": False,
                "skip_enabled": False,
                "play_visible": not playing[0],
                "play_rect": RECT if not playing[0] else None,
                "player_state": 1 if playing[0] else -1,
                "video_paused": not playing[0],
                "video_ready_state": 4 if playing[0] else 0,
                "video_current_time": current,
            }

        async def interact(action, _rect):
            actions.append(action)
            if action == "play":
                playing[0] = True
            return True

        result = await observe_youtube_playback(
            PlaybackPolicy("youtube", desired_primary_seconds=1),
            8,
            evaluate=evaluate,
            interact=interact,
            started_at=0,
            clock=lambda: now[0],
            checkpoint=lambda: None,
            poll_interval=0,
        )
        return result, actions

    result, actions = asyncio.run(scenario())
    assert actions == ["play"]
    assert result["ad_observed"] is False
    assert result["skippable_ad_observed"] is False
    assert result["skip_attempts"] == 0
    assert result["skip_confirmed"] is False
    assert result["primary_content_observed"] is True
    assert result["primary_goal_met"] is True


def test_unskippable_ad_can_end_naturally_before_primary_content():
    async def scenario():
        now = [0.0]
        actions = []

        async def evaluate():
            now[0] += 0.5
            ad = now[0] < 6
            return {
                "player_present": True,
                "video_present": True,
                "ad_showing": ad,
                "skip_visible": False,
                "skip_enabled": False,
                "play_visible": False,
                "player_state": 2 if ad else 1,
                "video_paused": ad,
                "video_ready_state": 4,
                "video_current_time": max(0, now[0] - 6),
            }

        async def interact(action, _rect):
            actions.append(action)
            return True

        result = await observe_youtube_playback(
            PlaybackPolicy("youtube", desired_primary_seconds=1),
            8,
            evaluate=evaluate,
            interact=interact,
            started_at=0,
            clock=lambda: now[0],
            checkpoint=lambda: None,
            poll_interval=0,
        )
        return result, actions

    result, actions = asyncio.run(scenario())
    assert actions == []
    assert result["ad_observed"] is True
    assert result["skippable_ad_observed"] is False
    assert result["skip_attempts"] == 0
    assert result["primary_content_observed"] is True
    assert result["primary_goal_met"] is True


def test_player_state_without_time_advance_is_not_primary_content():
    async def scenario():
        now = [0.0]

        async def evaluate():
            now[0] += 0.5
            return {
                "player_present": True,
                "video_present": True,
                "ad_showing": False,
                "player_state": 1,
                "video_paused": False,
                "video_ready_state": 4,
                "video_current_time": 0,
            }

        return await observe_youtube_playback(
            PlaybackPolicy("youtube", desired_primary_seconds=1),
            2,
            evaluate=evaluate,
            started_at=0,
            clock=lambda: now[0],
            checkpoint=lambda: None,
            poll_interval=0,
        )

    result = asyncio.run(scenario())
    assert result["primary_content_observed"] is False
    assert result["primary_content_seconds"] == 0
    assert result["quality"] == "unavailable"
    assert result["reason"] == "PRIMARY_CONTENT_NOT_OBSERVED"
