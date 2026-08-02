#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
target=${TT_TARGET:-x86_64-unknown-linux-gnu}
package_dir=${TT_PACKAGE_DIR:-$repo_root/dist/packages/$target}
python_bin=${PYTHON:-python}
args=()

if [[ ${TT_SMOKE_LAUNCH_UI:-0} == 1 ]]; then
  args+=(--launch-ui)
fi
if [[ $# -gt 0 ]]; then
  args+=("$@")
else
  mapfile -t artifacts < <(
    find "$package_dir" -maxdepth 1 -type f \
      \( -name '*.deb' -o -name '*.AppImage' \) -print | sort
  )
  if [[ ${#artifacts[@]} -ne 2 ]]; then
    echo "expected one Deb and one AppImage under $package_dir" >&2
    exit 1
  fi
  args+=("${artifacts[@]}")
fi

exec "$python_bin" "$repo_root/scripts/smoke-package-linux.py" "${args[@]}"
