#!/usr/bin/env python3
"""Recover capture-complete Sessions blocked by artifact contract failure."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from uuid import NAMESPACE_URL, uuid5

from traffictracer.analyze.job import AnalysisJob
from traffictracer.jobs.cancellation import CancellationToken
from traffictracer.jobs.models import AnalysisJobOptions, AnalysisJobSpec
from traffictracer.jobs.progress import ProgressReporter
from traffictracer.session.atomic import write_json_atomic
from traffictracer.session.finalization_repair import (
    REPAIR_REPORT_NAME,
    repair_finalization_failure,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pipeline_root", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="inspect eligibility without writing anything (the default)",
    )
    mode.add_argument(
        "--apply",
        action="store_true",
        help="write repaired Session manifests after the same strict checks",
    )
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="after repair, analyze recovered Sessions serially without recapture",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="report path (default: PIPELINE_ROOT/finalization-repair-report.json)",
    )
    return parser


def _load_object(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        payload = json.load(stream)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _session_manifest(run_root: Path) -> Path:
    candidates = [
        path
        for path in run_root.rglob("manifest.json")
        if not any(part.startswith(".") for part in path.relative_to(run_root).parts)
    ]
    if len(candidates) != 1:
        raise ValueError(
            f"expected exactly one Session manifest under {run_root}; "
            f"found {len(candidates)}"
        )
    return candidates[0]


def _has_expected_failure(run_root: Path) -> bool:
    manifests = list((run_root / ".batches").glob("*/batch-manifest.json"))
    if len(manifests) != 1:
        return False
    payload = _load_object(manifests[0])
    errors = [
        attempt.get("error")
        for child in payload.get("children", [])
        for attempt in child.get("attempts", [])
        if isinstance(attempt, dict)
    ]
    return any(
        isinstance(error, dict)
        and error.get("code") == "CONTRACT_VALIDATION_FAILED"
        and "session_v2/artifacts/" in str(error.get("message", ""))
        and "/role" in str(error.get("message", ""))
        for error in errors
    )


def _analyze(session_dir: Path, output_root: Path, pipeline: dict) -> dict:
    execution = pipeline.get("execution", {})
    options = execution.get("options", {}) if isinstance(execution, dict) else {}
    split_mode = str(options.get("pcap_split_mode", "unique_connections"))
    split = bool(options.get("capture_packets", True)) and split_mode != "none"
    job_id = str(uuid5(NAMESPACE_URL, session_dir.resolve().as_uri() + "#recovered-analysis"))
    reporter = ProgressReporter(job_id, lambda event: None, min_interval=1.0)
    spec = AnalysisJobSpec(
        job_id=job_id,
        session_dir=str(session_dir),
        output_root=str(output_root),
        options=AnalysisJobOptions(
            split_pcaps=split,
            pcap_split_mode=split_mode if split else "none",
            overwrite=True,
        ),
    )
    try:
        result = AnalysisJob(
            spec,
            progress=reporter,
            cancellation=CancellationToken(),
        ).run()
    except Exception as exc:
        return {
            "state": "failed",
            "error": str(exc).strip()[:1000] or type(exc).__name__,
        }
    return {
        "state": result.state.value,
        "session_id": result.session_id,
        "artifacts": list(result.artifacts),
    }


def run(args: argparse.Namespace) -> tuple[dict, int]:
    root = args.pipeline_root.expanduser().resolve(strict=True)
    manifest_path = root / "pipeline-manifest.json"
    pipeline = _load_object(manifest_path)
    if args.analyze and not args.apply:
        raise ValueError("--analyze requires --apply")
    runs = pipeline.get("runs")
    if not isinstance(runs, list):
        raise ValueError("pipeline manifest does not contain a runs array")

    results: list[dict] = []
    for run in sorted(runs, key=lambda item: int(item.get("ordinal", 0))):
        output = Path(str(run.get("output_path", ""))).resolve()
        try:
            output.relative_to(root / "runs")
            if not output.is_dir():
                raise ValueError("run output directory does not exist")
            if not _has_expected_failure(output):
                raise ValueError(
                    "run does not carry the expected Session artifact-role "
                    "contract failure"
                )
            session_manifest = _session_manifest(output)
            repaired = repair_finalization_failure(
                output,
                session_manifest.parent,
                apply=args.apply,
            )
            item = {
                "run_ordinal": run.get("ordinal"),
                "run_id": run.get("run_id"),
                **repaired.to_dict(),
            }
            if args.analyze and repaired.applied:
                item["analysis"] = _analyze(
                    session_manifest.parent, output, pipeline
                )
        except Exception as exc:
            item = {
                "run_ordinal": run.get("ordinal"),
                "run_id": run.get("run_id"),
                "eligible": False,
                "applied": False,
                "state": "error",
                "errors": [str(exc).strip()[:1000] or type(exc).__name__],
            }
        results.append(item)

    eligible = sum(item.get("eligible") is True for item in results)
    applied = sum(item.get("applied") is True for item in results)
    analyzed = sum(
        item.get("analysis", {}).get("state") == "completed" for item in results
    )
    failed_analysis = sum(
        item.get("analysis", {}).get("state") == "failed" for item in results
    )
    report = {
        "schema_version": 1,
        "pipeline_id": pipeline.get("pipeline_id"),
        "pipeline_root": str(root),
        "mode": "apply" if args.apply else "dry_run",
        "analysis_requested": args.analyze,
        "summary": {
            "runs": len(results),
            "eligible": eligible,
            "applied": applied,
            "analyzed": analyzed,
            "analysis_failed": failed_analysis,
            "ineligible": len(results) - eligible,
        },
        "pipeline_manifest_mutated": False,
        "sessions": results,
    }
    report_path = (args.report or (root / REPAIR_REPORT_NAME)).resolve()
    if args.apply:
        try:
            report_path.relative_to(root)
        except ValueError as exc:
            raise ValueError("repair report must stay inside pipeline root") from exc
        write_json_atomic(report_path, report)
    return report, 0 if eligible == len(results) and failed_analysis == 0 else 2


def main() -> int:
    args = _parser().parse_args()
    try:
        report, code = run(args)
    except Exception as exc:
        print(f"repair failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
