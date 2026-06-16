"""Event grouping — first pass over events to build SourceEntry map."""

from __future__ import annotations

from typing import Any

from .constants import NetLogConstants
from .source_entry import SourceEntry


def process_events(
    events: list[dict[str, Any]],
    constants: NetLogConstants,
) -> dict[int, SourceEntry]:
    """Group all events by source.id and extract descriptions.

    Returns a dict mapping source_id → SourceEntry.
    """
    entries: dict[int, SourceEntry] = {}

    for event in events:
        source = event.get("source")
        if not isinstance(source, dict):
            continue

        sid = source.get("id")
        if sid is None:
            continue

        if sid not in entries:
            entries[sid] = SourceEntry(
                source_id=sid,
                source_type=source.get("type", 0),
            )

        entries[sid].feed(event, constants)

    # Two-pass description: first register all, then resolve dependencies.
    # Uses a local registry dict instead of module-level global state.
    registry: dict[int, str] = {}
    for sid, entry in entries.items():
        registry[sid] = entry.description

    for entry in entries.values():
        entry.description = entry._extract_description(constants, registry)

    return entries


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
