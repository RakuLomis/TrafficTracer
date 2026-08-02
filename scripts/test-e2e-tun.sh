#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
target=${TT_TARGET:-x86_64-unknown-linux-gnu}
python_bin=${PYTHON:-python}
core=${TT_E2E_CORE:-$repo_root/dist/core/verge-mihomo-tt-$target}
worker=${TT_E2E_WORKER:-$repo_root/dist/worker/traffictracer-worker-$target}

if [[ $(uname -s) != Linux ]]; then
  echo "privileged TUN E2E is supported only on Linux" >&2
  exit 1
fi
if [[ ${EUID} -eq 0 ]]; then
  echo "run this gate as the unprivileged Runner user, not root" >&2
  exit 1
fi
for tool in sudo ip setpriv setcap getcap tshark dumpcap; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing privileged TUN E2E prerequisite: $tool" >&2
    exit 1
  fi
done
if ! sudo -n true; then
  echo "the controlled Runner must provide non-interactive sudo for network isolation" >&2
  exit 1
fi
if ! dumpcap -D >/dev/null 2>&1; then
  echo "dumpcap is not configured for capture by the unprivileged Runner user" >&2
  exit 1
fi
for binary in "$core" "$worker"; do
  if [[ ! -x "$binary" ]]; then
    echo "missing executable sidecar: $binary" >&2
    echo "run 'make check-component-lock' first" >&2
    exit 1
  fi
done

exec "$python_bin" "$repo_root/test/e2e/tun/run.py" \
  --core "$core" \
  --worker "$worker"
