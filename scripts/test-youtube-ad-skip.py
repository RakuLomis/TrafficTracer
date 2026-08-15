#!/usr/bin/env python3
"""Standalone headed-Chrome CDP test for YouTube ad skipping."""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import socket
import sys
import tempfile
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from traffictracer.capture.cdp import CDPCollector  # noqa: E402
from traffictracer.capture.chrome import (  # noqa: E402
    launch_chrome,
    terminate_chrome,
    wait_chrome_exit,
)


OBSERVE_EXPRESSION = r"""
(() => {
  const visible = (element) => {
    if (!element) return false;
    const style = getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    return style.display !== 'none' && style.visibility !== 'hidden' &&
      Number(style.opacity || 1) > 0 && rect.width > 0 && rect.height > 0;
  };
  const player = document.querySelector('#movie_player');
  const adModule = player && player.querySelector('.video-ads.ytp-ad-module');
  const skip = adModule && adModule.querySelector(
    '.ytp-skip-ad .ytp-skip-ad-button'
  );
  const play = player && player.querySelector(
    '.ytp-large-play-button, .ytp-play-button'
  );
  const video = player && player.querySelector('video');
  const rectOf = (element) => {
    if (!visible(element)) return null;
    const rect = element.getBoundingClientRect();
    return {
      x: rect.x, y: rect.y, width: rect.width, height: rect.height,
      center_x: rect.x + rect.width / 2,
      center_y: rect.y + rect.height / 2
    };
  };
  let playerState = null;
  let playerTime = null;
  try {
    playerState = player && typeof player.getPlayerState === 'function'
      ? Number(player.getPlayerState()) : null;
    playerTime = player && typeof player.getCurrentTime === 'function'
      ? Number(player.getCurrentTime()) : null;
  } catch (_) {}
  return {
    href: String(location.href || ''),
    title: String(document.title || '').slice(0, 160),
    player_present: Boolean(player),
    player_state: Number.isFinite(playerState) ? playerState : null,
    player_current_time: Number.isFinite(playerTime) ? playerTime : null,
    video_present: Boolean(video),
    video_paused: video ? Boolean(video.paused) : null,
    video_current_time: video ? Number(video.currentTime || 0) : null,
    video_ready_state: video ? Number(video.readyState || 0) : null,
    ad_showing: Boolean(
      (player && player.classList.contains('ad-showing')) || visible(adModule)
    ),
    ad_module_visible: visible(adModule),
    skip_visible: visible(skip),
    skip_rect: rectOf(skip),
    skip_class: skip ? String(skip.className || '').slice(0, 160) : null,
    skip_text: skip ? String(skip.textContent || '').trim().slice(0, 80) : null,
    play_visible: visible(play),
    play_rect: rectOf(play)
  };
})()
"""

DEFAULT_TEST_URLS = (
    "https://www.youtube.com/watch?v=QCmU6ZsW9Ao&list=RDQCmU6ZsW9Ao",
    "https://www.youtube.com/watch?v=PAZLLswtqxU",
    "https://www.youtube.com/watch?v=a8EYRkHa2YY",
)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def chrome_binary(value: str | None) -> str:
    candidates = [value] if value else [
        "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
    ]
    for candidate in candidates:
        if not candidate:
            continue
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
        path = Path(candidate)
        if path.is_file() and path.stat().st_mode & 0o111:
            return str(path.resolve())
    raise RuntimeError("Chrome executable was not found; pass --chrome-binary")


def validate_url(value: str) -> str:
    parsed = urlsplit(value)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not (
        host == "youtube.com" or host.endswith(".youtube.com") or host == "youtu.be"
    ):
        raise argparse.ArgumentTypeError("URL must be a YouTube HTTP(S) URL")
    return value


async def evaluate(collector: CDPCollector) -> dict:
    session_id = collector._page_session
    result = await collector.send(
        "Runtime.evaluate",
        {"expression": OBSERVE_EXPRESSION, "returnByValue": True},
        timeout=3,
        session_id=session_id,
    )
    if result.get("exceptionDetails"):
        raise RuntimeError("CDP observation JavaScript failed")
    value = (result.get("result") or {}).get("value")
    if not isinstance(value, dict):
        raise RuntimeError("CDP observation returned no object")
    return value


async def click_rect(collector: CDPCollector, rect: dict, label: str) -> None:
    x = float(rect["center_x"])
    y = float(rect["center_y"])
    session_id = collector._page_session
    await collector.send(
        "Input.dispatchMouseEvent",
        {"type": "mouseMoved", "x": x, "y": y},
        session_id=session_id,
    )
    await collector.send(
        "Input.dispatchMouseEvent",
        {"type": "mousePressed", "x": x, "y": y, "button": "left", "clickCount": 1},
        session_id=session_id,
    )
    await collector.send(
        "Input.dispatchMouseEvent",
        {"type": "mouseReleased", "x": x, "y": y, "button": "left", "clickCount": 1},
        session_id=session_id,
    )
    print(f"ACTION {label}: CDP mouse click at ({x:.1f}, {y:.1f})", flush=True)


def concise(observation: dict, elapsed: float) -> str:
    return (
        f"[{elapsed:5.1f}s] ad={observation.get('ad_showing')} "
        f"skip={observation.get('skip_visible')} "
        f"state={observation.get('player_state')} "
        f"paused={observation.get('video_paused')} "
        f"ready={observation.get('video_ready_state')} "
        f"time={observation.get('video_current_time')}"
    )


async def run_test(args: argparse.Namespace, work: Path) -> dict:
    port = free_port()
    profile = work / "chrome-profile"
    netlog = work / "netlog.json"
    process = launch_chrome(
        args.chrome_binary,
        "about:blank",
        str(netlog),
        str(profile),
        headless=False,
        remote_debugging_port=port,
        open_url=False,
    )
    collector = CDPCollector(port)
    started = time.monotonic()
    events: list[dict] = []
    skip_attempts = 0
    play_attempts = 0
    last_skip = -999.0
    last_play = -999.0
    skip_effect_observed = False
    prior_time: float | None = None
    advancing_samples = 0
    success = False
    reason = "TIMEOUT"
    last: dict = {}
    try:
        print(f"Chrome PID {process.pid}; CDP port {port}", flush=True)
        await collector.connect(retries=30, delay=0.25)
        await collector.setup()
        await collector.navigate(args.url, load_timeout=args.load_timeout, wait_for_load=False)
        print(f"Opened {args.url}", flush=True)
        while time.monotonic() - started < args.timeout:
            elapsed = time.monotonic() - started
            try:
                last = await evaluate(collector)
            except Exception as error:
                print(f"[{elapsed:5.1f}s] observation error: {error}", flush=True)
                await asyncio.sleep(args.interval)
                continue
            print(concise(last, elapsed), flush=True)
            if (
                skip_attempts > 0 and not last.get("ad_showing")
                and elapsed - last_skip <= 4.0
            ):
                skip_effect_observed = True
            current = last.get("video_current_time")
            if isinstance(current, (int, float)) and isinstance(prior_time, (int, float)):
                if current > prior_time + 0.15 and not last.get("ad_showing"):
                    advancing_samples += 1
                else:
                    advancing_samples = 0
            if isinstance(current, (int, float)):
                prior_time = float(current)

            if advancing_samples >= 2:
                if skip_effect_observed:
                    success = True
                    reason = "SKIP_CONFIRMED_AND_PRIMARY_VIDEO_ADVANCING"
                elif skip_attempts == 0:
                    reason = "NO_SKIPPABLE_AD_OBSERVED"
                else:
                    reason = "PRIMARY_ADVANCED_WITHOUT_CONFIRMED_SKIP_EFFECT"
                break

            if (
                last.get("skip_visible") and isinstance(last.get("skip_rect"), dict)
                and skip_attempts < args.max_skip_attempts
                and elapsed - last_skip >= args.click_cooldown
            ):
                skip_attempts += 1
                last_skip = elapsed
                await click_rect(collector, last["skip_rect"], f"skip #{skip_attempts}")
                events.append({"elapsed": round(elapsed, 3), "action": "skip"})
            elif (
                not last.get("ad_showing") and last.get("play_visible")
                and isinstance(last.get("play_rect"), dict)
                and last.get("player_state") != 1
                and play_attempts < args.max_play_attempts
                and elapsed - last_play >= args.click_cooldown
            ):
                play_attempts += 1
                last_play = elapsed
                await click_rect(collector, last["play_rect"], f"play #{play_attempts}")
                events.append({"elapsed": round(elapsed, 3), "action": "play"})
            await asyncio.sleep(args.interval)

        if not success and reason == "TIMEOUT":
            if skip_attempts == 0:
                reason = "SKIP_BUTTON_NOT_OBSERVED"
            elif last.get("ad_showing"):
                reason = "AD_REMAINED_AFTER_CDP_CLICK"
            else:
                reason = "VIDEO_DID_NOT_ADVANCE"
        result = {
            "schema_version": 1,
            "tested_at": datetime.now(timezone.utc).isoformat(),
            "url": args.url,
            "success": success,
            "outcome": (
                "passed" if success else
                "inconclusive" if reason in {
                    "NO_SKIPPABLE_AD_OBSERVED",
                    "PRIMARY_ADVANCED_WITHOUT_CONFIRMED_SKIP_EFFECT",
                } else "failed"
            ),
            "reason": reason,
            "skip_attempts": skip_attempts,
            "play_attempts": play_attempts,
            "skip_effect_observed": skip_effect_observed,
            "events": events,
            "last_observation": last,
        }
        print("RESULT " + json.dumps(result, ensure_ascii=False), flush=True)
        if args.hold_seconds > 0:
            print(f"Keeping the test browser visible for {args.hold_seconds:.1f}s", flush=True)
            await asyncio.sleep(args.hold_seconds)
        return result
    finally:
        try:
            await collector.close_browser()
        except Exception:
            pass
        try:
            await collector.close()
        finally:
            if not wait_chrome_exit(process, timeout=5):
                terminate_chrome(process, timeout=5)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "urls", nargs="*", type=validate_url, help="YouTube watch URL(s)",
    )
    result.add_argument(
        "--suite",
        action="store_true",
        help="run three built-in YouTube cases with a fresh profile per case",
    )
    result.add_argument("--chrome-binary", help="Chrome/Chromium executable")
    result.add_argument("--timeout", type=float, default=45.0, help="overall test seconds")
    result.add_argument("--load-timeout", type=float, default=30.0)
    result.add_argument("--interval", type=float, default=0.5)
    result.add_argument("--click-cooldown", type=float, default=2.0)
    result.add_argument("--max-skip-attempts", type=int, default=3)
    result.add_argument("--max-play-attempts", type=int, default=2)
    result.add_argument("--hold-seconds", type=float, default=8.0)
    result.add_argument("--output", type=Path, help="optional JSON result path")
    return result


def main() -> int:
    argument_parser = parser()
    args = argument_parser.parse_args()
    if args.suite and args.urls:
        argument_parser.error("--suite cannot be combined with positional URLs")
    urls = list(DEFAULT_TEST_URLS if args.suite else args.urls)
    if not urls:
        argument_parser.error("provide at least one URL or use --suite")
    if args.timeout <= 0 or args.interval <= 0 or args.click_cooldown < 0:
        raise SystemExit("timeout/interval must be positive and cooldown non-negative")
    if args.max_skip_attempts < 0 or args.max_play_attempts < 0:
        raise SystemExit("attempt limits must be non-negative")
    args.chrome_binary = chrome_binary(args.chrome_binary)
    results = []
    for index, url in enumerate(urls, start=1):
        print(f"CASE {index}/{len(urls)}: {url}", flush=True)
        case_args = argparse.Namespace(**vars(args))
        case_args.url = url
        try:
            with tempfile.TemporaryDirectory(
                prefix=f"traffictracer-youtube-skip-{index}-",
            ) as temp:
                result = asyncio.run(run_test(case_args, Path(temp)))
        except KeyboardInterrupt:
            print("Interrupted by user", file=sys.stderr)
            return 130
        except Exception as error:
            result = {
                "schema_version": 1,
                "tested_at": datetime.now(timezone.utc).isoformat(),
                "url": url,
                "success": False,
                "outcome": "failed",
                "reason": "TEST_ERROR",
                "error": str(error),
            }
            print("RESULT " + json.dumps(result, ensure_ascii=False), flush=True)
        results.append(result)
        print(
            f"CASE_RESULT {index}/{len(urls)}: "
            f"{result['outcome']} ({result['reason']})",
            flush=True,
        )

    payload = results[0] if len(results) == 1 else {
        "schema_version": 1,
        "suite": "youtube_ad_skip",
        "profile_policy": "fresh_per_case",
        "results": results,
        "counts": {
            state: sum(item.get("outcome") == state for item in results)
            for state in ("passed", "failed", "inconclusive")
        },
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
        print(f"Saved result: {args.output}")
    outcomes = {item["outcome"] for item in results}
    if "failed" in outcomes:
        return 2
    if "passed" in outcomes:
        return 0
    if outcomes == {"inconclusive"}:
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
