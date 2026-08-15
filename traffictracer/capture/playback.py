"""Bounded, evidence-preserving browser playback observation."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
import asyncio
from typing import Any

from traffictracer.playback import PlaybackPolicy


ObservationEvaluator = Callable[[], Awaitable[Mapping[str, Any]]]
PlaybackInteractor = Callable[[str, Mapping[str, Any]], Awaitable[bool]]
PlaybackProgress = Callable[[dict[str, Any]], None]


_YOUTUBE_OBSERVATION_TEMPLATE = r"""
(() => {
  const visible = (element) => {
    if (!element) return false;
    const style = window.getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    return style.display !== 'none' && style.visibility !== 'hidden' &&
      Number(style.opacity || 1) > 0 && rect.width > 0 && rect.height > 0;
  };
  const player = document.querySelector('#movie_player');
  const videos = Array.from(
    player ? player.querySelectorAll('video') : document.querySelectorAll('video')
  );
  const video = videos
    .filter(visible)
    .sort((left, right) => {
      const a = left.getBoundingClientRect();
      const b = right.getBoundingClientRect();
      return (b.width * b.height) - (a.width * a.height);
    })[0] || videos[0] || null;
  const adModule = player && player.querySelector('.video-ads.ytp-ad-module');
  const adOverlay = player && Array.from(player.querySelectorAll(
    '.ytp-ad-player-overlay, .video-ads.ytp-ad-module'
  )).some(visible);
  const adShowing = Boolean(
    (player && player.classList.contains('ad-showing')) || adOverlay
  );
  const skipSelectors = [
    '.ytp-skip-ad .ytp-skip-ad-button',
    '.ytp-ad-skip-button-modern',
    '.ytp-ad-skip-button'
  ];
  let skipButton = null;
  let skipSelector = null;
  if (adModule) {
    for (const selector of skipSelectors) {
      const candidate = adModule.querySelector(selector);
      if (visible(candidate) && !candidate.disabled) {
        skipButton = candidate;
        skipSelector = selector;
        break;
      }
    }
  }
  const playSelectors = ['.ytp-large-play-button', '.ytp-play-button'];
  let playButton = null;
  let playSelector = null;
  if (player) {
    for (const selector of playSelectors) {
      const candidate = player.querySelector(selector);
      if (visible(candidate) && !candidate.disabled) {
        playButton = candidate;
        playSelector = selector;
        break;
      }
    }
  }
  const actionableRect = (element) => {
    if (!visible(element)) return null;
    const rect = element.getBoundingClientRect();
    const centerX = rect.left + rect.width / 2;
    const centerY = rect.top + rect.height / 2;
    if (centerX < 0 || centerY < 0 || centerX >= innerWidth || centerY >= innerHeight) {
      return null;
    }
    const hit = document.elementFromPoint(centerX, centerY);
    if (!hit || !(hit === element || element.contains(hit))) return null;
    return {
      x: rect.x, y: rect.y, width: rect.width, height: rect.height,
      center_x: centerX, center_y: centerY
    };
  };
  let playerState = null;
  let playerTime = null;
  let playerDuration = null;
  try {
    playerState = player && typeof player.getPlayerState === 'function'
      ? Number(player.getPlayerState()) : null;
    playerTime = player && typeof player.getCurrentTime === 'function'
      ? Number(player.getCurrentTime()) : null;
    playerDuration = player && typeof player.getDuration === 'function'
      ? Number(player.getDuration()) : null;
  } catch (_) {}
  return {
    href: String(window.location.href || ''),
    player_present: Boolean(player),
    video_present: Boolean(video),
    ad_showing: adShowing || Boolean(skipButton),
    ad_module_visible: visible(adModule),
    skip_visible: Boolean(skipButton),
    skip_enabled: Boolean(skipButton && !skipButton.disabled),
    skip_selector: skipSelector,
    skip_rect: actionableRect(skipButton),
    play_visible: Boolean(playButton),
    play_selector: playSelector,
    play_rect: actionableRect(playButton),
    player_state: Number.isFinite(playerState) ? playerState : null,
    player_current_time: Number.isFinite(playerTime) ? playerTime : null,
    player_duration: Number.isFinite(playerDuration) ? playerDuration : null,
    video_candidate_count: videos.length,
    video_current_time: video ? Number(video.currentTime || 0) : 0,
    video_paused: video ? Boolean(video.paused) : true,
    video_ready_state: video ? Number(video.readyState || 0) : 0
  };
})()
"""


def youtube_observation_expression() -> str:
    """Return a fixed, read-only expression; no YAML value enters JavaScript."""

    return _YOUTUBE_OBSERVATION_TEMPLATE


async def observe_youtube_playback(
    policy: PlaybackPolicy,
    duration_seconds: float,
    *,
    evaluate: ObservationEvaluator,
    interact: PlaybackInteractor | None = None,
    started_at: float,
    clock: Callable[[], float],
    checkpoint: Callable[[], None],
    progress: PlaybackProgress | None = None,
    poll_interval: float = 0.5,
) -> dict[str, Any]:
    """Observe one fixed window and make bounded, evidence-based interactions."""

    deadline = started_at + max(0.0, duration_seconds)
    last_sample_at = started_at
    last_video_time: float | None = None
    last_phase = "preparation"
    phase_started_at = 0.0
    last_skip_at = float("-inf")
    last_play_at = float("-inf")
    skip_attempts = 0
    play_attempts = 0
    successful_samples = 0
    evaluation_errors = 0
    interaction_errors = 0
    primary_started_at: float | None = None
    primary_advancing_samples = 0
    ad_observed = False
    skippable_ad_observed = False
    skip_ad_cleared = False
    skip_confirmed = False
    diagnostic_counts = {
        "samples": 0,
        "player_present": 0,
        "video_present": 0,
        "ad_showing": 0,
        "skip_visible": 0,
        "playing": 0,
        "paused": 0,
        "ready": 0,
        "advancing": 0,
    }
    last_observation: dict[str, Any] = {}
    phase_seconds = {
        "preparation": 0.0,
        "advertisement": 0.0,
        "primary_content": 0.0,
        "other": 0.0,
    }
    events: list[dict[str, Any]] = [{
        "elapsed_seconds": 0.0,
        "phase": "preparation",
    }]

    def record_event(event: dict[str, Any]) -> None:
        if len(events) < 64:
            events.append(event)

    while True:
        checkpoint()
        before_evaluate = clock()
        if before_evaluate >= deadline:
            break
        elapsed_before = max(0.0, before_evaluate - started_at)
        interaction_ready = elapsed_before >= min(5.0, duration_seconds)
        observation: Mapping[str, Any] | None = None
        try:
            observation = await evaluate()
            successful_samples += 1
        except Exception:
            evaluation_errors += 1

        sampled_at = min(clock(), deadline)
        delta = max(0.0, sampled_at - last_sample_at)
        phase = "preparation" if primary_started_at is None else "other"
        current_video_time: float | None = None
        if observation is not None:
            try:
                current_video_time = float(
                    observation.get("video_current_time", 0.0)
                )
            except (TypeError, ValueError):
                current_video_time = None
            try:
                ready_state = int(
                    observation.get("video_ready_state", 0) or 0
                )
            except (TypeError, ValueError):
                ready_state = 0
            ad_showing = observation.get("ad_showing") is True
            advancing = (
                current_video_time is not None
                and last_video_time is not None
                and current_video_time > last_video_time + 0.02
                and current_video_time - last_video_time < 5.0
            )
            advancing_primary_sample = (
                not ad_showing
                and observation.get("video_present") is True
                and observation.get("video_paused") is False
                and ready_state >= 2
                and advancing
            )
            if advancing_primary_sample:
                primary_advancing_samples += 1
            else:
                primary_advancing_samples = 0
            primary_playing = primary_advancing_samples >= 2
            if ad_showing:
                ad_observed = True
                phase = "advertisement"
            elif primary_playing:
                phase = "primary_content"
                if primary_started_at is None:
                    primary_started_at = max(0.0, sampled_at - started_at)
            if observation.get("skip_visible") is True:
                skippable_ad_observed = True
            if (
                skip_attempts > 0 and not ad_showing
                and sampled_at - last_skip_at <= 4.0
            ):
                skip_ad_cleared = True
            if skip_ad_cleared and primary_playing and not skip_confirmed:
                skip_confirmed = True
                record_event({
                    "elapsed_seconds": round(
                        max(0.0, sampled_at - started_at), 3,
                    ),
                    "event": "skip_confirmed",
                })

            action: str | None = None
            rect: Mapping[str, Any] | None = None
            if (
                interact is not None
                and interaction_ready
                and policy.ad_policy == "click_visible_skip"
                and observation.get("skip_visible") is True
                and observation.get("skip_enabled") is True
                and isinstance(observation.get("skip_rect"), Mapping)
                and skip_attempts < 3
                and before_evaluate - last_skip_at >= 2.0
            ):
                action = "skip"
                rect = observation["skip_rect"]
            elif (
                interact is not None
                and interaction_ready
                and not ad_showing
                and observation.get("play_visible") is True
                and isinstance(observation.get("play_rect"), Mapping)
                and observation.get("player_state") != 1
                and play_attempts < 2
                and before_evaluate - last_play_at >= 2.0
            ):
                action = "play"
                rect = observation["play_rect"]
            if action is not None and rect is not None:
                try:
                    sent = await interact(action, rect)
                except Exception:
                    sent = False
                    interaction_errors += 1
                if action == "skip":
                    skip_attempts += 1
                    last_skip_at = sampled_at
                else:
                    play_attempts += 1
                    last_play_at = sampled_at
                record_event({
                    "elapsed_seconds": round(
                        max(0.0, sampled_at - started_at), 3,
                    ),
                    "event": f"{action}_{'sent' if sent else 'failed'}",
                })

            diagnostic_counts["samples"] += 1
            for key in (
                "player_present", "video_present", "ad_showing", "skip_visible",
            ):
                if observation.get(key) is True:
                    diagnostic_counts[key] += 1
            diagnostic_counts[
                "playing" if observation.get("video_paused") is False else "paused"
            ] += 1
            if ready_state >= 2:
                diagnostic_counts["ready"] += 1
            if advancing:
                diagnostic_counts["advancing"] += 1
            last_observation = {
                key: observation.get(key)
                for key in (
                    "player_present", "video_present", "ad_showing",
                    "ad_module_visible", "skip_visible", "skip_enabled",
                    "skip_selector", "play_visible", "play_selector",
                    "video_paused", "video_ready_state", "player_state",
                    "video_candidate_count",
                )
            }
            if current_video_time is not None:
                last_video_time = current_video_time

        phase_seconds[phase] += delta
        elapsed = max(0.0, sampled_at - started_at)
        if phase != last_phase:
            phase_started_at = elapsed
            record_event({
                "elapsed_seconds": round(elapsed, 3),
                "phase": phase,
            })
            last_phase = phase
        if progress is not None:
            progress({
                "elapsed_seconds": round(elapsed, 3),
                "duration_seconds": duration_seconds,
                "phase": phase,
                "phase_elapsed_seconds": round(
                    max(0.0, elapsed - phase_started_at), 3,
                ),
                "primary_content_observed": primary_started_at is not None,
                "primary_content_seconds": round(
                    phase_seconds["primary_content"], 3,
                ),
                "desired_primary_seconds": policy.desired_primary_seconds,
                "skip_attempts": skip_attempts,
                "play_attempts": play_attempts,
            })
        last_sample_at = sampled_at
        remaining = deadline - clock()
        if remaining <= 0:
            break
        await _cancellable_sleep(
            min(poll_interval, remaining), checkpoint,
        )

    ended_at = min(clock(), deadline)
    trailing = max(0.0, ended_at - last_sample_at)
    phase_seconds[last_phase] += trailing
    observed = max(0.0, ended_at - started_at)
    primary_seconds = phase_seconds["primary_content"]
    primary_observed = primary_started_at is not None
    goal_met = primary_seconds >= policy.desired_primary_seconds
    if goal_met:
        quality = "good"
        reason = None
    elif primary_observed:
        quality = "degraded"
        reason = "PRIMARY_DURATION_BELOW_TARGET"
    elif successful_samples:
        quality = "unavailable"
        reason = "PRIMARY_CONTENT_NOT_OBSERVED"
    else:
        quality = "unknown"
        reason = "PLAYBACK_STATE_UNKNOWN"

    return {
        "schema_version": 1,
        "provider": policy.provider,
        "ad_policy": policy.ad_policy,
        "observation_window_seconds": duration_seconds,
        "observed_total_seconds": round(observed, 3),
        "desired_primary_seconds": policy.desired_primary_seconds,
        "primary_content_seconds": round(primary_seconds, 3),
        "primary_content_observed": primary_observed,
        "primary_goal_met": goal_met,
        "quality": quality,
        "reason": reason,
        "phase_seconds": {
            key: round(value, 3)
            for key, value in phase_seconds.items()
        },
        "primary_content_started_at_seconds": (
            round(primary_started_at, 3)
            if primary_started_at is not None
            else None
        ),
        "ad_observed": ad_observed,
        "skippable_ad_observed": skippable_ad_observed,
        "skip_attempts": skip_attempts,
        "skip_confirmed": skip_confirmed,
        "play_attempts": play_attempts,
        "automation_available": successful_samples > 0,
        "evaluation_errors": evaluation_errors,
        "interaction_errors": interaction_errors,
        "end_reason": "observation_window_elapsed",
        "events": events,
        "diagnostics": {
            "counts": diagnostic_counts,
            "last_observation": last_observation,
        },
    }


async def _cancellable_sleep(
    seconds: float, checkpoint: Callable[[], None],
) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.0, seconds)
    while True:
        checkpoint()
        remaining = deadline - loop.time()
        if remaining <= 0:
            return
        await asyncio.sleep(min(0.05, remaining))
