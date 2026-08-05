"""Readable, path-safe Capture Group layout primitives."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
from pathlib import Path
import re
from urllib.parse import urlsplit


_SAFE_LABEL = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_UNSAFE_SLUG = re.compile(r"[^A-Za-z0-9.-]+")
_REPEATED_SEPARATOR = re.compile(r"[_-]{2,}")
MAX_URL_SLUG_LENGTH = 120


def normalize_page_types(entries: list[tuple[str | None, str]]) -> list[str]:
    """Return unique page directory labels in configuration order.

    Explicit page types are authoritative. Legacy run labels are normalized,
    and repeated legacy labels receive stable one-based suffixes.
    """

    bases: list[tuple[str, bool]] = []
    for explicit, run_label in entries:
        if explicit is not None:
            label = explicit.strip().lower()
            if not _SAFE_LABEL.fullmatch(label):
                raise ValueError("page_type must use lowercase letters, digits or hyphens")
            bases.append((label, True))
            continue
        legacy = run_label.strip().lower().replace("_", "-").replace(".", "-")
        aliases = {
            "video-mainpage": "main-page",
            "video-main-page": "main-page",
            "mainpage": "main-page",
        }
        label = aliases.get(legacy, legacy)
        label = re.sub(r"[^a-z0-9-]+", "-", label).strip("-") or "capture"
        bases.append((label[:64], False))

    totals: dict[str, int] = {}
    for label, explicit in bases:
        if not explicit:
            totals[label] = totals.get(label, 0) + 1

    used: set[str] = set()
    seen: dict[str, int] = {}
    output: list[str] = []
    for label, explicit in bases:
        seen[label] = seen.get(label, 0) + 1
        candidate = (
            label
            if explicit or totals.get(label, 0) == 1
            else f"{label}{seen[label]}"
        )
        if candidate in used:
            raise ValueError(f"duplicate page_type after normalization: {candidate}")
        used.add(candidate)
        output.append(candidate)
    return output


def safe_url_slug(url: str, *, max_length: int = MAX_URL_SLUG_LENGTH) -> str:
    """Build a readable URL directory component with a collision guard."""

    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL slug requires an absolute HTTP(S) URL")
    readable = "_".join(
        part for part in (parsed.scheme, parsed.netloc, parsed.path.strip("/")) if part
    )
    readable = _UNSAFE_SLUG.sub("_", readable)
    readable = _REPEATED_SEPARATOR.sub("_", readable).strip("_.-") or "url"
    needs_digest = bool(parsed.query or parsed.fragment or len(readable) > max_length)
    if needs_digest:
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:8]
        readable = f"{readable[: max_length - 10].rstrip('_.-')}__{digest}"
    return readable[:max_length]


def group_directory_name(started_at: datetime) -> str:
    if started_at.tzinfo is None:
        raise ValueError("capture group timestamp must be timezone-aware")
    return started_at.strftime("%Y%m%d-%H%M%S-%f")[:19]


def page_directory_name(page_type: str, url: str) -> str:
    if not _SAFE_LABEL.fullmatch(page_type):
        raise ValueError("unsafe page_type")
    return f"{page_type}__{safe_url_slug(url)}"


@dataclass(frozen=True)
class CapturePageLayout:
    group_root: Path
    domain: str
    page_type: str
    url: str

    @property
    def page_root(self) -> Path:
        return self.group_root / self.domain / page_directory_name(self.page_type, self.url)

    @property
    def raw_dir(self) -> Path:
        return self.page_root / "raw"

    @property
    def analysis_dir(self) -> Path:
        return self.page_root / "analysis"

    def create(self) -> None:
        self.raw_dir.mkdir(parents=True, mode=0o700)
        self.analysis_dir.mkdir(mode=0o700)
