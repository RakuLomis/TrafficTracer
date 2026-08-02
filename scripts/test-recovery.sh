#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
target=${TT_TARGET:-x86_64-unknown-linux-gnu}
python_bin=${PYTHON:-python}
core=${TT_E2E_CORE:-$repo_root/dist/core/verge-mihomo-tt-$target}
worker=${TT_E2E_WORKER:-$repo_root/dist/worker/traffictracer-worker-$target}

for binary in "$core" "$worker"; do
  if [[ ! -x "$binary" ]]; then
    echo "missing executable sidecar: $binary" >&2
    exit 1
  fi
done

exec "$python_bin" "$repo_root/test/e2e/recovery/run.py" \
  --core "$core" \
  --worker "$worker"
