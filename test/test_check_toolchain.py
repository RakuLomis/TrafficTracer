"""Tests for the Complete toolchain diagnostic script."""

import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-toolchain.sh"
TOOLS = (
    "python3", "go", "rustc", "cargo", "pnpm", "tshark", "dumpcap",
    "google-chrome", "pyinstaller",
)


def _fake_tools(directory: Path) -> None:
    for name in TOOLS:
        tool = directory / name
        if name == "python3":
            tool.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = -c ]; then exit 0; fi\n"
                "echo 'Python 3.12.0'\n"
            )
        else:
            tool.write_text(f"#!/bin/sh\necho '{name} test-version'\n")
        tool.chmod(0o755)


def _run(tool_dir: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["TT_TOOLCHAIN_PATH"] = str(tool_dir)
    return subprocess.run(
        ["/bin/bash", str(SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
    )


def test_toolchain_check_reports_all_tools_ready(tmp_path):
    _fake_tools(tmp_path)
    result = _run(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "SUMMARY\tpass=9\tfail=0" in result.stdout
    for key in ("python", "go", "rustc", "cargo", "pnpm", "tshark", "dumpcap", "chrome", "pyinstaller"):
        assert f"PASS\t{key}\t" in result.stdout


def test_toolchain_check_reports_missing_tool_and_fails(tmp_path):
    _fake_tools(tmp_path)
    (tmp_path / "go").unlink()
    result = _run(tmp_path)
    assert result.returncode != 0
    assert "FAIL\tgo\tinstall Go" in result.stdout
    assert "SUMMARY\tpass=8\tfail=1" in result.stdout
