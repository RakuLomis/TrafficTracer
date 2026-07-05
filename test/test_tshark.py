"""Tests for tshark manager (smoke-only, no live tshark required)."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import subprocess
from traffictracer.capture.tshark import stop_tshark


def test_stop_tshark_graceful():
    proc = subprocess.Popen(
        ["sleep", "2"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    stop_tshark(proc, timeout=3)
    assert proc.poll() is not None


def test_stop_tshark_already_dead():
    proc = subprocess.Popen(
        ["true"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    proc.wait()
    stop_tshark(proc, timeout=1)
    assert proc.poll() == 0


if __name__ == "__main__":
    test_stop_tshark_graceful()
    test_stop_tshark_already_dead()
    print("\n✓ All tshark manager tests passed!")
