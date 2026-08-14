"""Bounded, evidence-preserving browser playback observation."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
import asyncio
from typing import Any

from traffictracer.playback import PlaybackPolicy


ObservationEvaluator = Callable[[bool], Awaitable[Mapping[str, Any]]]
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
  const video = document.querySelector('video');
  const adOverlay = Array.from(document.querySelectorAll(
    '.ytp-ad-player-overlay, .video-ads.ytp-ad-module'
  )).some(visible);
  const adShowing = Boolean(
    (player && player.classList.contains('ad-showing')) || adOverlay
  );
  const selectorCandidates = Array.from(document.querySelectorAll(
    '.ytp-ad-skip-button, .ytp-ad-skip-button-modern, ' +
    '.ytp-skip-ad-button, button[class*="ad-skip"]'
  ));
  const semanticCandidates = Array.from(
    document.querySelectorAll('button, [role="button"]')
  ).filter((element) => {
    const label = [
      element.getAttribute('aria-label') || '',
      element.textContent || ''
    ].join(' ').trim();
    return /(^|\s)skip(\s|$)|跳过|スキップ|건너뛰기/i.test(label);
  });
  const skipButton = [...selectorCandidates, ...semanticCandidates]
    .find((element) => visible(element) && !element.disabled) || null;
  let skipClicked = false;
  if (__ALLOW_CLICK__ && adShowing && skipButton) {
    skipButton.click();
    skipClicked = true;
  }
  return {
    href: String(window.location.href || ''),
    player_present: Boolean(player),
    video_present: Boolean(video),
    ad_showing: adShowing,
    skip_visible: Boolean(skipButton),
    skip_clicked: skipClicked,
    video_current_time: video ? Number(video.currentTime || 0) : 0,
    video_paused: video ? Boolean(video.paused) : true,
    video_ready_state: video ? Number(video.readyState || 0) : 0
  };
})()
"""


def youtube_observation_expression(allow_click: bool) -> str:
    """Return a fixed internal expression; no YAML value enters JavaScript."""

    return _YOUTUBE_OBSERVATION_TEMPLATE.replace(
        "__ALLOW_CLICK__", "true" if allow_click else "false",
    )


async def observe_youtube_playback(
    policy: PlaybackPolicy,
    duration_seconds: float,
    *,
    evaluate: ObservationEvaluator,
    started_at: float,
    clock: Callable[[], float],
    checkpoint: Callable[[], None],
    progress: PlaybackProgress | None = None,
    poll_interval: float = 0.5,
) -> dict[str, Any]:
    """Observe one fixed window without filtering or extending capture."""

    deadline = started_at + max(0.0, duration_seconds)
    last_sample_at = started_at
    last_video_time: float | None = None
    last_phase = "preparation"
    phase_started_at = 0.0
    last_skip_at = float("-inf")
    skip_attempts = 0
    successful_samples = 0
    evaluation_errors = 0
    primary_started_at: float | None = None
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

    while True:
        checkpoint()
        before_evaluate = clock()
        if before_evaluate >= deadline:
            break
        allow_click = (
            policy.ad_policy == "click_visible_skip"
            and before_evaluate - last_skip_at >= 1.0
        )
        observation: Mapping[str, Any] | None = None
        try:
            observation = await evaluate(allow_click)
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
            primary_playing = (
                not ad_showing
                and observation.get("video_present") is True
                and observation.get("video_paused") is False
                and ready_state >= 2
                and advancing
            )
            if ad_showing:
                phase = "advertisement"
            elif primary_playing:
                phase = "primary_content"
                if primary_started_at is None:
                    primary_started_at = max(0.0, sampled_at - started_at)
            if observation.get("skip_clicked") is True:
                skip_attempts += 1
                last_skip_at = sampled_at
                events.append({
                    "elapsed_seconds": round(
                        max(0.0, sampled_at - started_at), 3,
                    ),
                    "event": "skip_clicked",
                })
            if current_video_time is not None:
                last_video_time = current_video_time

        phase_seconds[phase] += delta
        elapsed = max(0.0, sampled_at - started_at)
        if phase != last_phase:
            phase_started_at = elapsed
            events.append({
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
                "primary_content_seconds": round(
                    phase_seconds["primary_content"], 3,
                ),
                "desired_primary_seconds": (
                    policy.desired_primary_seconds
                ),
                "skip_attempts": skip_attempts,
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
    goal_met = primary_seconds >= policy.desired_primary_seconds
    if goal_met:
        quality = "good"
        reason = None
    elif primary_started_at is not None:
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
        "skip_attempts": skip_attempts,
        "automation_available": successful_samples > 0,
        "evaluation_errors": evaluation_errors,
        "end_reason": "observation_window_elapsed",
        "events": events,
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
