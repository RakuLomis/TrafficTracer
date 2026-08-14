"""Validated playback-observation policy shared by configuration and jobs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


PLAYBACK_PROVIDERS = {"youtube"}
PLAYBACK_AD_POLICIES = {"click_visible_skip"}


@dataclass(frozen=True)
class PlaybackPolicy:
    """Optional bounded playback goal for one browser visit."""

    provider: str
    ad_policy: str = "click_visible_skip"
    desired_primary_seconds: int = 25

    def __post_init__(self) -> None:
        if self.provider not in PLAYBACK_PROVIDERS:
            raise ValueError("playback provider must be youtube")
        if self.ad_policy not in PLAYBACK_AD_POLICIES:
            raise ValueError(
                "playback ad_policy must be click_visible_skip"
            )
        if (
            isinstance(self.desired_primary_seconds, bool)
            or not isinstance(self.desired_primary_seconds, int)
            or not 1 <= self.desired_primary_seconds <= 86_400
        ):
            raise ValueError(
                "playback desired_primary_seconds must be an integer "
                "between 1 and 86400"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "ad_policy": self.ad_policy,
            "desired_primary_seconds": self.desired_primary_seconds,
        }

    @classmethod
    def from_dict(
        cls, payload: Mapping[str, Any] | None,
    ) -> PlaybackPolicy | None:
        if payload is None:
            return None
        data = dict(payload)
        return cls(
            provider=data["provider"],
            ad_policy=data.get("ad_policy", "click_visible_skip"),
            desired_primary_seconds=data.get(
                "desired_primary_seconds", 25,
            ),
        )
