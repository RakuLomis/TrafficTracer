#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
target="${TT_TARGET:-x86_64-unknown-linux-gnu}"
ui_dir="${TT_UI_DIR:-${repo_root}/components/clash-verge-rev}"
mihomo_dir="${TT_MIHOMO_DIR:-${repo_root}/components/mihomo}"
core_dist_dir="${TT_CORE_DIST_DIR:-${repo_root}/dist/core}"
worker_dist_dir="${TT_WORKER_DIST_DIR:-${repo_root}/dist/worker}"
core_artifact="${core_dist_dir}/verge-mihomo-tt-${target}"
worker_artifact="${worker_dist_dir}/traffictracer-worker-${target}"
core_build_script="${TT_BUILD_CORE_SCRIPT:-${repo_root}/scripts/build-core.sh}"
worker_build_script="${TT_BUILD_WORKER_SCRIPT:-${repo_root}/scripts/build-worker.sh}"
pnpm_bin="${TT_PNPM_BIN:-pnpm}"
mode="dev"

case "${1:-}" in
  "") ;;
  --prepare-only) mode="prepare" ;;
  *)
    echo "usage: $0 [--prepare-only]" >&2
    exit 2
    ;;
esac

case "$target" in
  x86_64-unknown-linux-gnu) ;;
  *)
    echo "error: unsupported Complete development target: $target" >&2
    exit 2
    ;;
esac

for required_dir in "$ui_dir" "$mihomo_dir"; do
  if [[ ! -d "$required_dir" ]]; then
    echo "error: Complete component is missing: $required_dir" >&2
    echo "run make bootstrap first" >&2
    exit 2
  fi
done
for build_script in "$core_build_script" "$worker_build_script"; do
  if [[ ! -x "$build_script" ]]; then
    echo "error: build script is not executable: $build_script" >&2
    exit 2
  fi
done
if ! command -v "$pnpm_bin" >/dev/null 2>&1; then
  echo "error: pnpm command is unavailable: $pnpm_bin" >&2
  exit 2
fi

"$core_build_script" "$core_artifact"
TT_WORKER_DIST_DIR="$worker_dist_dir" "$worker_build_script"

for artifact in "$core_artifact" "$worker_artifact"; do
  if [[ ! -x "$artifact" ]]; then
    echo "error: required Complete artifact is not executable: $artifact" >&2
    exit 3
  fi
done

(
  cd "$ui_dir"
  MIHOMO_TRAFFIC_TRACER_BIN="$core_artifact" \
    TRAFFICTRACER_WORKER_BIN="$worker_artifact" \
    "$pnpm_bin" prebuild --force "$target"
)

core_sidecar="$ui_dir/src-tauri/sidecar/verge-mihomo-tt-$target"
worker_sidecar="$ui_dir/src-tauri/sidecar/traffictracer-worker-$target"
for pair in "$core_artifact:$core_sidecar" "$worker_artifact:$worker_sidecar"; do
  source_path="${pair%%:*}"
  target_path="${pair#*:}"
  if [[ ! -x "$target_path" ]]; then
    echo "error: prebuild did not inject executable sidecar: $target_path" >&2
    exit 3
  fi
  if ! cmp -s "$source_path" "$target_path"; then
    echo "error: injected sidecar is stale or differs from its artifact: $target_path" >&2
    exit 3
  fi
done

print_component_revision() {
  local label="$1" directory="$2" revision dirty
  if revision="$(git -C "$directory" rev-parse HEAD 2>/dev/null)"; then
    dirty=""
    if [[ -n "$(git -C "$directory" status --porcelain --untracked-files=no)" ]]; then
      dirty="+dirty"
    fi
    printf 'Component %-10s %s%s\n' "$label" "$revision" "$dirty"
  else
    printf 'Component %-10s unknown (not a Git worktree)\n' "$label"
  fi
}

print_component_revision "mihomo" "$mihomo_dir"
print_component_revision "ui" "$ui_dir"
printf 'Artifact hashes:\n'
sha256sum "$core_artifact" "$worker_artifact"
printf 'Injected sidecars are current for %s.\n' "$target"

if [[ "$mode" == "prepare" ]]; then
  exit 0
fi

cd "$ui_dir"
exec "$pnpm_bin" dev
