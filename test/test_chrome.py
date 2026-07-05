"""Tests for Chrome manager (no live Chrome required)."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import subprocess
import tempfile
from traffictracer.capture.chrome import launch_chrome, kill_chrome


def test_kill_chrome():
    proc = subprocess.Popen(
        ["sleep", "5"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    kill_chrome(proc)
    assert proc.poll() is not None


def test_kill_chrome_already_exited():
    proc = subprocess.Popen(
        ["true"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    proc.wait()
    kill_chrome(proc)
    assert proc.poll() == 0


if __name__ == "__main__":
    test_kill_chrome()
    test_kill_chrome_already_exited()
    print("\n✓ All Chrome manager tests passed!")
