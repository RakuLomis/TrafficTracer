#!/usr/bin/env bash
set -u

search_path="${TT_TOOLCHAIN_PATH:-$PATH}"
pass_count=0
fail_count=0

find_tool() {
  local candidate directory
  for candidate in "$@"; do
    IFS=':' read -r -a directories <<< "$search_path"
    for directory in "${directories[@]}"; do
      [[ -n "$directory" ]] || directory='.'
      if [[ -x "$directory/$candidate" && ! -d "$directory/$candidate" ]]; then
        printf '%s\n' "$directory/$candidate"
        return 0
      fi
    done
  done
  return 1
}

report_pass() {
  printf 'PASS\t%s\t%s\n' "$1" "$2"
  pass_count=$((pass_count + 1))
}

report_fail() {
  printf 'FAIL\t%s\t%s\n' "$1" "$2"
  fail_count=$((fail_count + 1))
}

check_version_tool() {
  local key="$1" remediation="$2" version_arg="$3"
  shift 3
  local tool
  if ! tool="$(find_tool "$@")"; then
    report_fail "$key" "$remediation"
    return
  fi
  local output version
  if ! output="$($tool "$version_arg" 2>&1)"; then
    report_fail "$key" "found $tool but version check failed; $remediation"
    return
  fi
  version="${output%%$'\n'*}"
  report_pass "$key" "${version:-$tool}"
}

python_bin="$(find_tool python3 python 2>/dev/null || true)"
if [[ -z "$python_bin" ]]; then
  report_fail python "install Python 3.12 or newer"
elif "$python_bin" -c 'import sys; raise SystemExit(0 if (3, 12) <= sys.version_info < (4, 0) else 1)' >/dev/null 2>&1; then
  report_pass python "$($python_bin --version 2>&1)"
else
  report_fail python "Python 3.12 or newer (but below 4.0) is required"
fi

check_version_tool go "install Go from https://go.dev/dl/" version go
check_version_tool rustc "install Rust with rustup" --version rustc
check_version_tool cargo "install Cargo with rustup" --version cargo
check_version_tool pnpm "enable Corepack and install the repository pnpm version" --version pnpm
check_version_tool tshark "install Wireshark/tshark" --version tshark
check_version_tool dumpcap "install dumpcap and configure capture permissions" --version dumpcap
check_version_tool chrome "install Google Chrome or Chromium" --version google-chrome google-chrome-stable chromium chromium-browser
check_version_tool pyinstaller "install PyInstaller in the Complete build environment" --version pyinstaller

printf 'SUMMARY\tpass=%d\tfail=%d\n' "$pass_count" "$fail_count"
[[ "$fail_count" -eq 0 ]]
