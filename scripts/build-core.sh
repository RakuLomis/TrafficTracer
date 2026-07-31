#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
target="${TT_TARGET:-x86_64-unknown-linux-gnu}"
mihomo_dir="${TT_MIHOMO_DIR:-${repo_root}/components/mihomo}"
dist_dir="${TT_CORE_DIST_DIR:-${repo_root}/dist/core}"
output="${1:-${dist_dir}/verge-mihomo-tt-${target}}"
build_script="${TT_CORE_BUILD_SCRIPT:-${mihomo_dir}/scripts/build-complete-core.sh}"

case "$target" in
  x86_64-unknown-linux-gnu) ;;
  *)
    echo "error: unsupported Complete development target: $target" >&2
    exit 2
    ;;
esac

if [[ ! -x "$build_script" ]]; then
  echo "error: Complete core build script is not executable: $build_script" >&2
  exit 2
fi

mkdir -p "$(dirname -- "$output")"
"$build_script" "$output"

if [[ ! -x "$output" ]]; then
  echo "error: Complete core build did not produce an executable: $output" >&2
  exit 3
fi

if [[ "${TT_CORE_SMOKE:-0}" == "1" ]]; then
  smoke_script="${TT_CORE_SMOKE_SCRIPT:-${mihomo_dir}/scripts/smoke-complete-core.sh}"
  if [[ ! -x "$smoke_script" ]]; then
    echo "error: Complete core smoke script is not executable: $smoke_script" >&2
    exit 2
  fi
  "$smoke_script" "$output"
fi

printf 'Complete core artifact: %s\n' "$output"
sha256sum "$output"
