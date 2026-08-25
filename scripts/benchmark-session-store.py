#!/usr/bin/env python3
"""Reproducible, unprivileged SessionStore scaling benchmark."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
from time import perf_counter
from typing import Any, Callable
from uuid import NAMESPACE_URL, UUID, uuid5


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from traffictracer.jobs.models import JobState  # noqa: E402
from traffictracer.layout import group_directory_name  # noqa: E402
from traffictracer.session.atomic import write_json_atomic  # noqa: E402
from traffictracer.session.manifest import (  # noqa: E402
    ComponentVersion,
    ComponentVersions,
    SessionManifest,
    SessionTarget,
)
from traffictracer.session.recovery import RecoveryManager  # noqa: E402
from traffictracer.session.store import (  # noqa: E402
    CorruptSessionError,
    SessionStore,
)


BASE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sessions", type=int, default=1000)
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args()
    if args.sessions < 4:
        parser.error("--sessions must be at least 4")
    if args.repetitions < 1:
        parser.error("--repetitions must be positive")
    return args


def versions() -> ComponentVersions:
    component = ComponentVersion("benchmark", "0" * 40)
    return ComponentVersions(component, component, component)


def deterministic_ids(count: int) -> tuple[UUID, ...]:
    return tuple(
        uuid5(NAMESPACE_URL, f"traffictracer-session-benchmark-{index}")
        for index in range(count)
    )


def populate(root: Path, count: int) -> tuple[SessionStore, tuple[SessionManifest, ...]]:
    ids = iter(deterministic_ids(count))
    store = SessionStore(root, id_factory=lambda: next(ids))
    manifests: list[SessionManifest] = []
    component_versions = versions()

    for index in range(count):
        created_at = BASE_TIME + timedelta(seconds=index)
        manifest = store.create(
            job_id=str(uuid5(NAMESPACE_URL, f"benchmark-job-{index}")),
            target=SessionTarget(
                f"https://site-{index}.example/page",
                f"site-{index}.example",
            ),
            component_versions=component_versions,
            now=created_at,
            page_type="benchmark-page",
            capture_group=group_directory_name(
                BASE_TIME + timedelta(minutes=index // 100)
            ),
        )
        manifest = manifest.transition(
            JobState.PREPARING,
            now=created_at + timedelta(milliseconds=100),
        ).transition(
            JobState.CAPTURING,
            now=created_at + timedelta(milliseconds=200),
        )
        terminal = (
            JobState.INTERRUPTED if index == count - 1 else JobState.COMPLETED
        )
        manifest = manifest.transition(
            terminal,
            now=created_at + timedelta(milliseconds=300),
        )
        store.save(manifest)
        manifests.append(manifest)

    corrupt_id = uuid5(NAMESPACE_URL, "benchmark-corrupt")
    corrupt_dir = root / f"broken_{corrupt_id}"
    corrupt_dir.mkdir()
    (corrupt_dir / "manifest.json").write_text("{not-json", encoding="utf-8")

    duplicate = manifests[0]
    duplicate_dir = root / f"duplicate_{duplicate.session_id}"
    duplicate_dir.mkdir()
    payload = duplicate.to_dict()
    payload["session_dir"] = str(duplicate_dir.resolve())
    write_json_atomic(duplicate_dir / "manifest.json", payload)
    return store, tuple(manifests)


def measure(operation: Callable[[], Any], repetitions: int) -> dict[str, Any]:
    samples: list[float] = []
    for _ in range(repetitions):
        started = perf_counter()
        operation()
        samples.append((perf_counter() - started) * 1000)
    ordered = sorted(samples)
    return {
        "samples_ms": [round(value, 3) for value in samples],
        "minimum_ms": round(ordered[0], 3),
        "median_ms": round(ordered[len(ordered) // 2], 3),
        "maximum_ms": round(ordered[-1], 3),
    }


def benchmark(root: Path, count: int, repetitions: int) -> dict[str, Any]:
    store, manifests = populate(root, count)
    target = manifests[count // 2]
    interrupted = manifests[-1]
    target_scope_id = Path(target.session_dir).relative_to(root).parts[0]
    scan = store.scan()
    duplicate_detected = False
    try:
        store.get(manifests[0].session_id)
    except CorruptSessionError:
        duplicate_detected = True

    return {
        "schema_version": 1,
        "fixture": {
            "requested_sessions": count,
            "valid_manifests": len(scan.sessions),
            "corrupt_manifests": len(scan.corrupt),
            "duplicate_detected": duplicate_detected,
            "interrupted_session_id": interrupted.session_id,
        },
        "measurements": {
            "store_construction": measure(
                lambda: SessionStore(root), repetitions
            ),
            "scan": measure(store.scan, repetitions),
            "scan_scope": measure(
                lambda: store.scan_scope(target_scope_id), repetitions
            ),
            "get": measure(lambda: store.get(target.session_id), repetitions),
            "warm_catalog_get": measure(
                lambda: SessionStore(root).get(target.session_id), repetitions
            ),
            "artifact_path": measure(
                lambda: store.artifact_path(target.session_id, "recovery.json"),
                repetitions,
            ),
            "known_session_artifact_path": measure(
                lambda: store.artifact_path_for_session(
                    target.session_id,
                    target.session_dir,
                    "recovery.json",
                ),
                repetitions,
            ),
            "scope_for_job": measure(
                lambda: store.scope_for_job(target.job_id), repetitions
            ),
            "recovery_discovery": measure(
                lambda: RecoveryManager(
                    SessionStore(root),
                    restore_tracing=lambda snapshot: None,
                    fingerprint=lambda pid: None,
                    terminate=lambda pid: None,
                ).recover(),
                repetitions,
            ),
        },
    }


def main() -> int:
    args = parse_args()
    with tempfile.TemporaryDirectory(
        prefix="traffictracer-session-store-benchmark-"
    ) as temporary:
        result = benchmark(Path(temporary), args.sessions, args.repetitions)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
