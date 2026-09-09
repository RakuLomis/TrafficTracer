"""Event grouping — first pass over events to build SourceEntry map."""

from __future__ import annotations

from typing import Any, Callable, Iterable

from .constants import NetLogConstants
from .source_entry import SourceEntry


def process_events(
    events: Iterable[dict[str, Any]],
    constants: NetLogConstants,
    *,
    progress: Callable[[str, int, int | None], None] | None = None,
) -> dict[int, SourceEntry]:
    """Group all events by source.id and extract descriptions.

    Returns a dict mapping source_id → SourceEntry.
    """
    entries: dict[int, SourceEntry] = {}
    total = len(events) if hasattr(events, "__len__") else None

    for index, raw_event in enumerate(events):
        if progress is not None and index % 1024 == 0:
            progress("normalize_events", index, total)
        source = raw_event.get("source")
        if not isinstance(source, dict):
            continue

        sid = source.get("id")
        if sid is None:
            continue
        event = _canonical_event(raw_event, constants)
        canonical_source = event["source"]

        if sid not in entries:
            entries[sid] = SourceEntry(
                source_id=sid,
                source_type=canonical_source.get("type", 0),
            )

        entries[sid].feed(event, constants)

    # Two-pass description: first register all, then resolve dependencies.
    # Uses a local registry dict instead of module-level global state.
    registry: dict[int, str] = {}
    for sid, entry in entries.items():
        registry[sid] = entry.description

    for index, entry in enumerate(entries.values()):
        if progress is not None and index % 1024 == 0:
            progress("describe_sources", index, len(entries))
        entry.description = entry._extract_description(constants, registry)

    if progress is not None:
        progress("describe_sources", len(entries), len(entries))

    return entries


def _canonical_event(
    event: dict[str, Any],
    constants: NetLogConstants,
) -> dict[str, Any]:
    """Return a shallow copy with dump-specific numeric types normalized."""
    normalized = dict(event)
    source = dict(event.get("source") or {})
    source["type"] = constants.canonical_source_type(int(source.get("type", 0)))
    normalized["source"] = source
    normalized["type"] = constants.canonical_event_type(int(event.get("type", 0)))

    params = event.get("params")
    if isinstance(params, dict):
        dependency = params.get("source_dependency")
        if isinstance(dependency, dict) and dependency.get("type") is not None:
            params = dict(params)
            dependency = dict(dependency)
            dependency["type"] = constants.canonical_source_type(
                int(dependency["type"])
            )
            params["source_dependency"] = dependency
            normalized["params"] = params
    return normalized


def find_events_by_type(
    entries: dict[int, SourceEntry],
    source_type: int,
) -> list[SourceEntry]:
    """Filter entries by source type."""
    return [e for e in entries.values() if e.source_type == source_type]


def find_events_by_event_type(
    entries: dict[int, SourceEntry],
    event_type: int,
) -> list[SourceEntry]:
    """Filter entries that contain at least one event of the given event type."""
    result = []
    for entry in entries.values():
        if any(e.get("type") == event_type for e in entry.entries):
            result.append(entry)
    return result
