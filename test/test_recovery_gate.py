"""Wiring and responsive-wait checks for the recovery E2E gate."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_capture_duration_uses_cancellable_wait():
    source = (ROOT / "traffictracer" / "capture" / "job.py").read_text()
    # BrowserHealthToken delegates cancellation and additionally detects exit.
    assert "browser_health.wait(self.spec.duration_seconds)" in source
    assert "time.sleep(self.spec.duration_seconds)" not in source


def test_recovery_gate_covers_all_fault_stages():
    source = (ROOT / "test" / "e2e" / "recovery" / "run.py").read_text()
    for marker in ("chrome.test", "dumpcap.test", "analysis.test", "crash.test"):
        assert marker in source
    assert "process.kill()" in source
    assert 'manifest["state"] != "interrupted"' in source


def test_makefile_exposes_recovery_gate():
    makefile = (ROOT / "Makefile").read_text()
    assert "test-recovery: check-component-lock" in makefile
    assert "scripts/test-recovery.sh" in makefile
