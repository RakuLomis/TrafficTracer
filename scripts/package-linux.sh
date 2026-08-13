#!/usr/bin/env bash
set -euo pipefail

umask 022

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
target="${TT_TARGET:-x86_64-unknown-linux-gnu}"
ui_dir="${TT_UI_DIR:-${repo_root}/components/clash-verge-rev}"
prepare_script="${TT_PREPARE_SCRIPT:-${repo_root}/scripts/build-ui.sh}"
pnpm_bin="${TT_PNPM_BIN:-pnpm}"
python_bin="${PYTHON:-python}"
product_version="$(PYTHONPATH="$repo_root" "$python_bin" -c 'from traffictracer.version import COMPLETE_VERSION; print(COMPLETE_VERSION)')"
ui_version="$("$python_bin" -c 'import json, pathlib, sys; print(json.loads(pathlib.Path(sys.argv[1]).read_text())["version"])' "$ui_dir/src-tauri/tauri.conf.json")"
bundle_version="${ui_version}+traffictracer.${product_version}"
release_audit_script="${TT_RELEASE_AUDIT_SCRIPT:-${repo_root}/scripts/release-audit.py}"
tauri_target_dir="${TT_TAURI_TARGET_DIR:-${ui_dir}/target}"
output_dir="${TT_PACKAGE_OUTPUT_DIR:-${repo_root}/dist/packages/traffictracer-complete-v${product_version}-linux-x86_64}"

case "$target" in
  x86_64-unknown-linux-gnu) ;;
  *)
    echo "error: unsupported Complete package target: $target" >&2
    exit 2
    ;;
esac

if [[ ! -d "$ui_dir" ]]; then
  echo "error: Complete UI component is missing: $ui_dir" >&2
  echo "run make bootstrap first" >&2
  exit 2
fi
if [[ ! -x "$prepare_script" ]]; then
  echo "error: Complete prepare script is not executable: $prepare_script" >&2
  exit 2
fi
if ! command -v "$pnpm_bin" >/dev/null 2>&1; then
  echo "error: pnpm command is unavailable: $pnpm_bin" >&2
  exit 2
fi
if [[ -e "$output_dir" ]]; then
  echo "error: package output already exists: $output_dir" >&2
  echo "remove it or set TT_PACKAGE_OUTPUT_DIR to a new path" >&2
  exit 2
fi

output_parent="$(dirname -- "$output_dir")"
mkdir -p "$output_parent"
stage_dir="$(mktemp -d "${output_parent}/.traffictracer-package.XXXXXX")"
marker="$(mktemp "${output_parent}/.traffictracer-build.XXXXXX")"
cleanup() {
  rm -rf -- "$stage_dir"
  rm -f -- "$marker"
}
trap cleanup EXIT

TT_TARGET="$target" TT_UI_DIR="$ui_dir" "$prepare_script" --prepare-only

# Tauri's AppImage bundler preserves the source icon mode for the root icon.
# Normalize packaged asset inputs after preparation so a permissive developer
# umask cannot make an installed asset group- or world-writable.
for asset_dir in "$ui_dir/src-tauri/icons" "$ui_dir/src-tauri/resources"; do
  if [[ -d "$asset_dir" ]]; then
    find "$asset_dir" -type f -exec chmod go-w -- {} +
  fi
done

if [[ -z "${TAURI_SIGNING_PRIVATE_KEY:-}" ]]; then
  tauri_config="$("$python_bin" -c 'import json, sys; print(json.dumps({"version": sys.argv[1], "bundle": {"createUpdaterArtifacts": False}}))' "$bundle_version")"
  echo "Updater signing key is unset; building verified unsigned packages."
else
  tauri_config="$("$python_bin" -c 'import json, sys; print(json.dumps({"version": sys.argv[1]}))' "$bundle_version")"
fi
tauri_args=(tauri build --target "$target" --bundles deb,appimage --config "$tauri_config")

(
  cd "$ui_dir"
  CARGO_TARGET_DIR="$tauri_target_dir" "$pnpm_bin" "${tauri_args[@]}"
)

bundle_root="$tauri_target_dir/$target/release/bundle"
mapfile -t debs < <(find "$bundle_root/deb" -maxdepth 1 -type f -name '*.deb' -newer "$marker" -print 2>/dev/null)
mapfile -t appimages < <(find "$bundle_root/appimage" -maxdepth 1 -type f -name '*.AppImage' -newer "$marker" -print 2>/dev/null)
if [[ "${#debs[@]}" -ne 1 || "${#appimages[@]}" -ne 1 ]]; then
  echo "error: expected one fresh Deb and one fresh AppImage" >&2
  echo "found Deb=${#debs[@]} AppImage=${#appimages[@]} under $bundle_root" >&2
  exit 3
fi

(
  cd "$ui_dir"
  "$pnpm_bin" verify:linux-bundle -- \
    --target "$target" \
    --sidecars src-tauri/sidecar \
    "${debs[0]}" "${appimages[0]}"
)

deb_name="TrafficTracer-Complete_${product_version}_linux_x86_64.deb"
appimage_name="TrafficTracer-Complete_${product_version}_linux_x86_64.AppImage"
cp -- "${debs[0]}" "$stage_dir/$deb_name"
cp -- "${appimages[0]}" "$stage_dir/$appimage_name"
(
  cd "$stage_dir"
  sha256sum -- ./*.deb ./*.AppImage >SHA256SUMS
)
service_commit="$("$python_bin" -c 'import pathlib, sys, yaml; print(yaml.safe_load(pathlib.Path(sys.argv[1]).read_text())["components"]["clash_verge_service"]["commit"])' "$repo_root/complete/components.lock.yaml")"
cat >"$stage_dir/VERSION" <<EOF
product=TrafficTracer Complete
version=$product_version
platform=linux-x86_64
target=$target
bundle_version=$bundle_version
EOF

{
  printf 'target=%s\n' "$target"
  printf 'product_version=%s\n' "$product_version"
  printf 'bundle_version=%s\n' "$bundle_version"
  printf 'traffictracer=%s\n' "$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || printf unknown)"
  printf 'mihomo=%s\n' "$(git -C "$repo_root/components/mihomo" rev-parse HEAD 2>/dev/null || printf unknown)"
  printf 'ui=%s\n' "$(git -C "$ui_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
  printf 'service=%s\n' "$service_commit"
} >"$stage_dir/COMPONENTS"

if [[ "${TT_RELEASE_AUDIT:-0}" == 1 ]]; then
  if [[ ! -x "$release_audit_script" ]]; then
    echo "error: release audit script is unavailable: $release_audit_script" >&2
    exit 2
  fi
  "$python_bin" "$release_audit_script" --package-dir "$stage_dir" --write
fi

mv -- "$stage_dir" "$output_dir"
trap - EXIT
rm -f -- "$marker"

printf 'TrafficTracer Complete Linux packages:\n'
find "$output_dir" -maxdepth 1 -type f -printf '  %f\n' | sort
printf 'Package directory: %s\n' "$output_dir"
