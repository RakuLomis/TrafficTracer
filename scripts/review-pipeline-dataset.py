#!/usr/bin/env python3
"""Read-only review of final pipeline samples; never rewrites captures/manifests."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys


def review(root: Path) -> dict:
    root = root.resolve(strict=True)
    pipeline = json.loads((root / "pipeline-manifest.json").read_text())
    sessions = {}
    for manifest in root.glob("runs/*/*/*/*/manifest.json"):
        content = json.loads(manifest.read_text())
        sid = content["session_id"]
        if sid in sessions:
            raise ValueError(f"Duplicate Session ID: {sid}")
        sessions[sid] = (manifest, content)
    samples = []
    artifacts = []
    blocks = {}
    candidates = {run["candidate_ordinal"] for run in pipeline["runs"]}
    for run in pipeline["runs"]:
        target = next(t for t in pipeline["targets"] if t["index"] == run["target_index"])
        quality = run.get("quality") or {}
        row = {
            "repetition": run["repetition_index"], "target_index": run["target_index"],
            "url": target["url"], "candidate": run["candidate_ordinal"],
            "protocol": run.get("observed_protocol", ""), "run_state": run["state"],
            "session_ids": run["session_ids"], "prior_session_ids": run.get("prior_session_ids", []),
            "capture": quality.get("capture_integrity", {}).get("state", "unavailable"),
            "correlation": quality.get("correlation", {}).get("state", "unavailable"),
            "application": quality.get("application", {}).get("state", "unavailable"),
            "application_issues": quality.get("application_issues", []),
            "activity_outcomes": [], "audit_issues": [],
        }
        for sid in run["session_ids"]:
            found = sessions.get(sid)
            if found is None:
                row["audit_issues"].append(f"missing_session:{sid}")
                continue
            manifest, session = found
            directory = manifest.parent.resolve()
            if not directory.is_relative_to(root):
                raise ValueError("Session path escapes pipeline root")
            summary = directory / "analysis/summary.json"
            if summary.exists():
                outcome = json.loads(summary.read_text())
                row["activity_outcomes"].append(outcome.get("activity_outcome", {}))
            else:
                row["audit_issues"].append(f"missing_summary:{sid}")
            for artifact in session.get("artifacts", []):
                path = (directory / artifact["path"]).resolve()
                if not path.is_relative_to(directory):
                    row["audit_issues"].append(f"unsafe_path:{artifact['path']}")
                    continue
                expected = artifact.get("size_bytes")
                actual = path.stat().st_size if path.is_file() else None
                as_of = artifact.get("size_semantics") == "as_of"
                if (type(expected) is not int or expected < 0 or actual is None
                        or actual != expected and not (as_of and actual >= expected)):
                    kind = ("missing" if actual is None else "invalid_recorded_size"
                            if type(expected) is not int or expected < 0
                            else "grew" if actual > expected else "shrank")
                    artifacts.append({"session_id": sid, "path": artifact["path"],
                                      "recorded_bytes": expected, "actual_bytes": actual, "kind": kind})
                    row["audit_issues"].append(f"{kind}:{artifact['path']}")
        row["all_planes_passed"] = run["state"] == "completed" and all(
            row[k] == "passed" for k in ("capture", "correlation", "application"))
        row["capture_correlation_passed"] = bool(run["session_ids"]) and all(
            row[k] == "passed" for k in ("capture", "correlation"))
        samples.append(row)
        blocks.setdefault((row["repetition"], row["target_index"]), []).append(row)
    paired = []
    for (repetition, index), rows in sorted(blocks.items()):
        complete = len(rows) == len(candidates) and {r["candidate"] for r in rows} == candidates
        paired.append({"repetition": repetition, "target_index": index, "url": rows[0]["url"],
                       "all_planes_passed": complete and all(r["all_planes_passed"] for r in rows),
                       "capture_correlation_passed": complete and all(r["capture_correlation_passed"] for r in rows)})
    return {"schema_version": 1, "pipeline_id": pipeline["pipeline_id"],
            "pipeline_state": pipeline["state"], "read_only": True,
            "selection_note": "Quality eligibility is separate from artifact audit and is not causal validity.",
            "final_runs": len(samples), "discovered_sessions": len(sessions),
            "all_planes_paired_blocks": sum(b["all_planes_passed"] for b in paired),
            "capture_correlation_paired_blocks": sum(b["capture_correlation_passed"] for b in paired),
            "artifact_discrepancies": artifacts, "paired_blocks": paired, "samples": samples}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pipeline_root", type=Path)
    parser.add_argument("--format", choices=("json", "csv"), default="json")
    args = parser.parse_args()
    result = review(args.pipeline_root)
    if args.format == "json":
        json.dump(result, sys.stdout, indent=2, ensure_ascii=False)
        print()
    else:
        rows = result["samples"]
        if rows:
            writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0]))
            writer.writeheader()
            for row in rows:
                writer.writerow({k: json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v
                                 for k, v in row.items()})


if __name__ == "__main__":
    main()
