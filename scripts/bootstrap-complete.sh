#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
cd "$repo_root"

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is required" >&2
  exit 2
fi

if [[ ! -f .gitmodules ]]; then
  echo "error: .gitmodules is missing; run this command from the Complete branch" >&2
  exit 2
fi

echo "Synchronizing Complete component URLs..."
git submodule sync --recursive

echo "Initializing pinned Complete components..."
git submodule update --init --recursive

for component in components/mihomo components/clash-verge-rev; do
  if [[ ! -d "$component" ]]; then
    echo "error: failed to initialize $component" >&2
    exit 3
  fi
  printf '%-30s %s\n' "$component" "$(git -C "$component" rev-parse --short=12 HEAD)"
done

echo "Complete component bootstrap finished."
