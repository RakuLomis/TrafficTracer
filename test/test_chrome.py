"""Tests for Chrome manager (no live Chrome required)."""

import os
import signal
import sys
import subprocess
from unittest.mock import patch, MagicMock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.capture.chrome import (
    ChromeOwnership,
    LinuxProcessIdentity,
    OwnedChromeProcess,
    launch_chrome,
    terminate_chrome,
    wait_chrome_exit,
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


def test_launch_chrome_minimal(tmp_path):
    fake_chrome = tmp_path / "fake-chrome"
    fake_chrome.write_text("#!/bin/sh\nsleep 0.2\n", encoding="utf-8")
    fake_chrome.chmod(0o755)
    proc = launch_chrome(
        binary=str(fake_chrome),
        url="about:blank",
        netlog_path="/tmp/test_netlog.json",
        user_data_dir="/tmp/test-profile",
        headless=True,
        open_url=False,
    )
    proc.wait(timeout=5)
    assert proc.poll() == 0


def test_launch_chrome_background_flags():
    with patch("subprocess.Popen") as mock_popen:
        mock_popen.return_value = MagicMock()
        launch_chrome(
            binary="google-chrome",
            url="https://example.com",
            netlog_path="/tmp/nl.json",
            user_data_dir="/tmp/prof",
            headless=True,
            disable_background_networking=True,
            open_url=False,
        )
        cmd = mock_popen.call_args[0][0]
        assert mock_popen.call_args.kwargs["start_new_session"] is sys.platform.startswith("linux")
        assert "--disable-background-networking" in cmd
        assert "--disable-component-update" in cmd
        assert "--disable-sync" in cmd


def test_launch_chrome_no_background_flags_by_default():
    with patch("subprocess.Popen") as mock_popen:
        mock_popen.return_value = MagicMock()
        launch_chrome(
            binary="google-chrome",
            url="https://example.com",
            netlog_path="/tmp/nl.json",
            user_data_dir="/tmp/prof",
            headless=True,
            open_url=False,
        )
        cmd = mock_popen.call_args[0][0]
        assert "--disable-background-networking" not in cmd


if __name__ == "__main__":
    test_terminate_chrome()
    test_terminate_chrome_already_exited()
    test_wait_chrome_exit_exits()
    test_wait_chrome_exit_timeout()
    test_launch_chrome_minimal()
    test_launch_chrome_background_flags()
    test_launch_chrome_no_background_flags_by_default()
    print("\n✓ All Chrome manager tests passed!")


def test_cancelled_chrome_cleanup_uses_short_grace_before_kill():
    from traffictracer.jobs.cancellation import CancellationToken

    token = CancellationToken()
    token.cancel("cancel navigation")
    proc = MagicMock()
    proc.pid = 123
    proc.poll.return_value = None
    proc.wait.side_effect = [subprocess.TimeoutExpired("chrome", 1), 0]
    terminate_chrome(proc, timeout=15, cancellation=token)
    proc.wait.assert_any_call(timeout=1.0)
    proc.kill.assert_called_once()


class _ExitedMain:
    pid = 100
    returncode = 0

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode


def _identity(pid, pgid, start, command):
    return LinuxProcessIdentity(
        pid=pid,
        pgid=pgid,
        start_token=start,
        executable="/opt/chrome",
        command=tuple(command),
    )


def _owned(processes, signals, *, clock=None, clear_on=None):
    profile = "/tmp/job-profile"

    def signal_group(pgid, sig):
        signals.append(("group", pgid, sig))
        if clear_on is None or sig == clear_on:
            processes.clear()

    values = clock if clock is not None else [0.0]
    return OwnedChromeProcess(
        _ExitedMain(),
        ChromeOwnership(100, 100, "start-100", "/opt/chrome", profile),
        inspect=lambda pid: next((item for item in processes if item.pid == pid), None),
        processes=lambda: tuple(processes),
        signal_pid=lambda pid, sig: signals.append(("pid", pid, sig)),
        signal_group=signal_group,
        monotonic=lambda: values[0],
        sleep=lambda seconds: values.__setitem__(0, values[0] + max(seconds, 0.1)),
    )


def test_owned_chrome_finds_profile_child_after_main_exits_and_is_idempotent():
    processes = [
        _identity(101, 100, "child", ["/opt/chrome", "--user-data-dir=/tmp/job-profile"])
    ]
    signals = []
    chrome = _owned(processes, signals)

    assert chrome.poll() is None
    chrome.terminate()
    chrome.terminate()
    assert signals == [("group", 100, signal.SIGTERM)]
    assert chrome.poll() == 0


def test_owned_chrome_rejects_reused_pid_and_unrelated_chrome():
    processes = [
        _identity(100, 100, "reused", ["/usr/bin/unrelated"]),
        _identity(101, 100, "other", ["/opt/chrome", "--user-data-dir=/tmp/other-profile"]),
        _identity(202, 202, "user", ["/opt/chrome", "--user-data-dir=/home/user/profile"]),
    ]
    signals = []
    chrome = _owned(processes, signals)

    assert chrome.owned_pids() == ()
    chrome.terminate()
    chrome.kill()
    assert signals == []


def test_owned_chrome_escalates_term_timeout_to_kill_without_global_scan():
    processes = [
        _identity(100, 100, "start-100", ["/opt/chrome", "--user-data-dir=/tmp/job-profile"]),
        _identity(101, 100, "child", ["/opt/chrome", "--type=renderer"]),
        _identity(202, 202, "user", ["/opt/chrome", "--user-data-dir=/home/user/profile"]),
    ]
    signals = []
    chrome = _owned(
        processes,
        signals,
        clock=[0.0],
        clear_on=signal.SIGKILL,
    )

    terminate_chrome(chrome, timeout=0.2)

    assert signals == [
        ("group", 100, signal.SIGTERM),
        ("group", 100, signal.SIGKILL),
    ]
