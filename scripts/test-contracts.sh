#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
python_bin="${PYTHON:-python}"
go_bin="${GO:-go}"
cargo_bin="${CARGO:-cargo}"
golden_dir="${repo_root}/test/fixtures/tracing"
contract_dir="${repo_root}/test/fixtures/contracts"
mihomo_dir="${repo_root}/components/mihomo"
ui_dir="${repo_root}/components/clash-verge-rev"

for directory in "$golden_dir" "$mihomo_dir" "$ui_dir"; do
  if [[ ! -d "$directory" ]]; then
    echo "error: Complete contract input is missing: $directory" >&2
    exit 2
  fi
done
for tool in "$python_bin" "$go_bin" "$cargo_bin"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: contract tool is unavailable: $tool" >&2
    exit 2
  fi
done

cd "$repo_root"
"$python_bin" -m pytest -q \
  test/test_job_contract.py \
  test/test_worker_api_contract.py \
  test/test_session_flow_contract.py \
  test/test_contracts.py \
  test/test_cross_contract_golden.py

(
  cd "$mihomo_dir"
  TRAFFICTRACER_GOLDEN_DIR="$golden_dir" \
    "$go_bin" test ./component/tracer -run '^TestCompleteGoldenEvents$'
)

(
  cd "$ui_dir"
  TRAFFICTRACER_GOLDEN_DIR="$golden_dir" \
  TRAFFICTRACER_CONTRACT_DIR="$contract_dir" \
    "$cargo_bin" test --manifest-path src-tauri/Cargo.toml \
      golden_complete_ --lib
)

echo "TrafficTracer Complete Python/Go/Rust contract gate passed."
