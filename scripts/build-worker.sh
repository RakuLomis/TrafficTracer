#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
python_bin="${PYTHON:-python3}"
dist_dir="${TT_WORKER_DIST_DIR:-${repo_root}/dist/worker}"
work_dir="${TT_WORKER_BUILD_DIR:-${repo_root}/build/pyinstaller-worker}"
worker_name="traffictracer-worker-x86_64-unknown-linux-gnu"

if ! "$python_bin" -c 'import PyInstaller' >/dev/null 2>&1; then
  echo "error: PyInstaller is required; install requirements-build.txt" >&2
  exit 2
fi

mkdir -p "$dist_dir" "$work_dir"
"$python_bin" -m PyInstaller \
  --noconfirm \
  --clean \
  --distpath "$dist_dir" \
  --workpath "$work_dir" \
  "${repo_root}/packaging/traffictracer-worker.spec"

worker_path="${dist_dir}/${worker_name}"
if [[ ! -x "$worker_path" ]]; then
  echo "error: Worker artifact was not produced: $worker_path" >&2
  exit 3
fi

"$python_bin" "${repo_root}/scripts/smoke-worker.py" -- "$worker_path"
printf 'Worker artifact: %s\n' "$worker_path"
