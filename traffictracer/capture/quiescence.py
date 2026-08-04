"""Final Chrome ownership barrier for serial capture safety."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import time
from typing import Callable

from .chrome import OwnedChromeProcess


@dataclass(frozen=True)
class ChromeQuiescenceReport:
    profile: str
    ownership_verified: bool
    remaining_pids: tuple[int, ...]


class ChromeCleanupIncomplete(RuntimeError):
    code = "CHROME_CLEANUP_INCOMPLETE"

    def __init__(self, report: ChromeQuiescenceReport) -> None:
        self.report = report
        pids = ",".join(str(pid) for pid in report.remaining_pids) or "unknown"
        super().__init__(
            f"{self.code}: managed Chrome processes remain for the capture profile (pids={pids})"
        )


def verify_chrome_quiescence(
    process,
    profile: str | Path,
    *,
    timeout: float = 2.0,
    poll_interval: float = 0.05,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> ChromeQuiescenceReport:
    """Wait until the exact managed identity/profile has no live process."""
    if timeout < 0 or poll_interval <= 0:
        raise ValueError("Chrome quiescence timings must be positive")
    expected_profile = str(Path(profile).resolve())
    ownership_verified = isinstance(process, OwnedChromeProcess)
    if ownership_verified and process.ownership.profile != expected_profile:
        raise ChromeCleanupIncomplete(
            ChromeQuiescenceReport(
                profile=expected_profile,
                ownership_verified=False,
                remaining_pids=process.owned_pids(),
            )
        )

    deadline = monotonic() + timeout
    while True:
        remaining = (
            process.owned_pids()
            if ownership_verified
            else (() if process is None or process.poll() is not None else (process.pid,))
        )
        if not remaining:
            return ChromeQuiescenceReport(
                profile=expected_profile,
                ownership_verified=ownership_verified,
                remaining_pids=(),
            )
        if monotonic() >= deadline:
            raise ChromeCleanupIncomplete(
                ChromeQuiescenceReport(
                    profile=expected_profile,
                    ownership_verified=ownership_verified,
                    remaining_pids=tuple(sorted(remaining)),
                )
            )
        sleep(poll_interval)
