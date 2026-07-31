#!/usr/bin/env python3
"""TrafficTracer Analysis — correlate and split captured traffic data.

Usage:
  python analyze.py --session output/2025-07-05_14-30-00/
"""

import argparse
import json
from pathlib import Path
import sys
from uuid import uuid4

from traffictracer.analyze.job import AnalysisJob
from traffictracer.jobs.cancellation import CancellationToken
from traffictracer.jobs.models import AnalysisJobOptions, AnalysisJobSpec
from traffictracer.jobs.progress import ProgressReporter


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="TrafficTracer Analysis Pipeline",
    )
    parser.add_argument("--session", "-s", required=True,
                        help="Path to capture session directory")
    parser.add_argument("--json", action="store_true",
                        help="Print a machine-readable Job result")
    args = parser.parse_args(argv)

    try:
        session = Path(args.session).expanduser().resolve()
        spec = AnalysisJobSpec(
            job_id=str(uuid4()),
            session_dir=str(session),
            output_root=str(session.parent),
            options=AnalysisJobOptions(overwrite=True),
        )
        events = []
        result = AnalysisJob(
            spec,
            progress=ProgressReporter(spec.job_id, events.append),
            cancellation=CancellationToken(),
        ).run()
        if args.json:
            print(json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True))
        else:
            correlation = next(
                (item for item in result.artifacts if item.endswith("correlation.json")),
                "results/correlation.json",
            )
            print(f"Correlation results: {session / correlation}")
        return 0
    except KeyboardInterrupt:
        print("Analysis cancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
