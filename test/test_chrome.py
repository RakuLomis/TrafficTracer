"""Tests for Chrome manager (no live Chrome required)."""

import os
import sys
import subprocess
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.capture.chrome import (
    launch_chrome, terminate_chrome, wait_chrome_exit,
)


def test_terminate_chrome():
    proc = subprocess.Popen(
        ["sleep", "5"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    terminate_chrome(proc)
    assert proc.poll() is not None


def test_terminate_chrome_already_exited():
    proc = subprocess.Popen(
        ["true"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    proc.wait()
    terminate_chrome(proc)
    assert proc.poll() == 0


def test_wait_chrome_exit_exits():
    proc = subprocess.Popen(
        ["sleep", "1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_chrome_exit(proc, timeout=5) is True
    assert proc.poll() is not None


def test_wait_chrome_exit_timeout():
    proc = subprocess.Popen(
        ["sleep", "30"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_chrome_exit(proc, timeout=1) is False
    assert proc.poll() is None
    terminate_chrome(proc)


def test_launch_chrome_minimal():
    proc = launch_chrome(
        binary="echo",
        url="about:blank",
        netlog_path="/tmp/test_netlog.json",
        user_data_dir="/tmp/test-profile",
        headless=True,
        open_url=False,
    )
    proc.wait(timeout=5)
    assert proc.poll() == 0


if __name__ == "__main__":
    test_terminate_chrome()
    test_terminate_chrome_already_exited()
    test_wait_chrome_exit_exits()
    test_wait_chrome_exit_timeout()
    test_launch_chrome_minimal()
    print("\n✓ All Chrome manager tests passed!")
