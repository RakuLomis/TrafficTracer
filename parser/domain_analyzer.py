"""Domain analysis — group connections by domain, site relation, and address.

Programmatic usage::

    from parser.domain_analyzer import get_domain_connections

    results = get_domain_connections("chrome-net-export-log.json", "bilibili.com")
    # results is a list of dicts:
    # [{"name": "https://www.bilibili.com",
    #   "site": "https://bilibili.com",
    #   "relation": "same_site",
    #   "connection_num": 1,
    #   "connection_detail": [{"local_address": "...", "remote_address": "..."}]}]
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .source_entry import SourceEntry
from .event_processor import process_events
from .constants import (
    NetLogConstants,
    SRC_HTTP_STREAM_JOB,
    SRC_SOCKET,
    SRC_HTTP_PROXY_CONNECT_JOB,
)
from .dependency_graph import (
    trace_chain,
    _build_children_index,
    _parse_ip_port,
    extract_deps_from_event,
)


@dataclass
class DomainGroup:
    """A group of connections sharing the same name and site relation."""

    name: str           # e.g. "https://www.bilibili.com"
    site: str           # e.g. "https://bilibili.com"
    relation: str       # "same_site" or "cross_site"
    connection_num: int
    connection_detail: list[dict[str, Any]]


def analyze_domain(
    entries: dict[int, SourceEntry],
    domain: str,
) -> list[DomainGroup]:
    """Analyze connections for a target domain.

    Scans HTTP_STREAM_JOB (type 5) and SOCKET (type 3) entries for
    group_id annotations matching *domain*, then traces each to find
    address-bearing HTTP_PROXY_CONNECT_JOB entries.

    Returns groups keyed by (name, relation), sorted by connection count
    descending.
    """
    children_index = _build_children_index(entries)

    # Collect matching entries: (name, site, relation, entry)
    matching: list[tuple[str, str, str, SourceEntry]] = []

    for entry in entries.values():
        if entry.source_type not in (SRC_HTTP_STREAM_JOB, SRC_SOCKET):
            continue

        for event in entry.entries:
            gid = (event.get("params") or {}).get("group_id")
            if not isinstance(gid, str):
                continue

            parsed = _parse_group_id(gid)
            if parsed is None:
                continue

            name, site, relation = parsed
            if domain.lower() in site.lower() or domain.lower() in name.lower():
                matching.append((name, site, relation, entry))
                break

    # Group by (name, relation) and collect addresses
    groups: dict[tuple[str, str], DomainGroup] = {}
    seen_sources: set[int] = set()

    for name, site, relation, entry in matching:
        key = (name, relation)
        if key not in groups:
            groups[key] = DomainGroup(
                name=name, site=site, relation=relation,
                connection_num=0, connection_detail=[],
            )

        # Walk the dependency chain to find address-bearing entries.
        chain = trace_chain(entry.source_id, entries)

        # Also search downstream for HTTP_PROXY_CONNECT_JOB children.
        chain_ids = {e.source_id for e in chain}
        proxy_entries: list[SourceEntry] = []
        for chain_entry in chain:
            for child_id in children_index.get(chain_entry.source_id, []):
                if child_id in chain_ids:
                    continue
                child = entries.get(child_id)
                if (child is not None
                        and child.source_type == SRC_HTTP_PROXY_CONNECT_JOB
                        and child not in proxy_entries):
                    proxy_entries.append(child)

        # Extract addresses from chain + downstream proxy entries.
        for src in chain + proxy_entries:
            for event in src.entries:
                params = event.get("params") or {}
                local = params.get("local_address")
                remote = params.get("remote_address")
                if not local and not remote:
                    continue

                if src.source_id not in seen_sources:
                    seen_sources.add(src.source_id)
                    groups[key].connection_num += 1

                detail = {
                    "local_address": str(local) if local else "",
                    "remote_address": str(remote) if remote else "",
                }
                if detail not in groups[key].connection_detail:
                    groups[key].connection_detail.append(detail)

    return sorted(groups.values(), key=lambda g: -g.connection_num)


def _parse_group_id(gid: str) -> tuple[str, str, str] | None:
    """Parse a group_id of the form 'URL <site relation>'.

    Returns (name, site, relation) or None.

    Examples:
        'https://www.bilibili.com <https://bilibili.com same_site>'
        'https://s1.hdslb.com <https://bilibili.com cross_site>'
        'pm/https://api.bilibili.com <https://bilibili.com same_site>'
    """
    if "<" not in gid or ">" not in gid:
        return None

    idx = gid.rfind(" <")
    if idx == -1:
        return None

    name = gid[:idx].strip()
    rest = gid[idx + 1:].strip()

    if not (rest.startswith("<") and rest.endswith(">")):
        return None

    inner = rest[1:-1]
    parts = inner.rsplit(" ", 1)
    if len(parts) != 2:
        return None

    site, relation = parts[0], parts[1]
    return name, site, relation


def get_domain_connections(
    filepath: str,
    domain: str,
) -> list[dict[str, Any]]:
    """Convenience: load a NetLog file and return domain analysis as a plain list.

    This is the recommended entry point for programmatic usage.  It handles
    JSON loading, event processing, and domain analysis in one call.

    Args:
        filepath: Path to a NetLog JSON file (or ZIP archive).
        domain: Target domain, e.g. ``"bilibili.com"``.

    Returns:
        A list of dicts with keys ``name``, ``site``, ``relation``,
        ``connection_num``, and ``connection_detail``, sorted by connection
        count descending.

    Example::

        from parser.domain_analyzer import get_domain_connections

        results = get_domain_connections("chrome-net-export-log.json", "bilibili.com")
        for item in results:
            print(item["name"], item["relation"], item["connection_num"])
    """
    fp = Path(filepath)
    if not fp.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    if fp.suffix.lower() == ".zip":
        import zipfile
        with zipfile.ZipFile(fp, "r") as zf:
            json_files = [n for n in zf.namelist() if n.lower().endswith(".json")]
            if not json_files:
                raise ValueError("No .json file found in ZIP")
            raw = json.loads(zf.read(json_files[0]).decode("utf-8"))
    else:
        with open(fp, "r", encoding="utf-8") as f:
            raw = json.load(f)

    constants = NetLogConstants(raw.get("constants") or {})
    events = raw.get("events") or []
    entries = process_events(events, constants)

    return _to_dict_list(analyze_domain(entries, domain))


def _to_dict_list(groups: list[DomainGroup]) -> list[dict[str, Any]]:
    """Convert DomainGroup objects to plain dicts."""
    return [
        {
            "name": g.name,
            "site": g.site,
            "relation": g.relation,
            "connection_num": g.connection_num,
            "connection_detail": g.connection_detail,
        }
        for g in groups
    ]
