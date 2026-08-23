"""Independent fixtures for every Complete environment diagnostic."""

import os
from pathlib import Path
import shutil
import subprocess

import traffictracer.diagnostics.environment as environment
from traffictracer.diagnostics import EnvironmentSpec, diagnose_environment
from traffictracer.diagnostics.models import DiagnosticSeverity


def test_controller_diagnostics_distinguish_unreachable_and_wrong_core(monkeypatch):
    monkeypatch.setattr(
        environment,
        "_controller_get",
        lambda *args: (_ for _ in ()).throw(ConnectionError("refused")),
    )
    unavailable = environment.check_controller("unix:///tmp/mihomo.sock")
    assert unavailable.code == "CORE_TRACING_UNAVAILABLE"
    assert unavailable.severity is DiagnosticSeverity.ERROR
    assert unavailable.remediation

    monkeypatch.setattr(environment, "_controller_get", lambda *args: {"version": 1})
    mismatch = environment.check_controller("http://127.0.0.1:9090")
    assert mismatch.code == "CORE_CAPABILITY_MISMATCH"
    assert mismatch.details["missing_capabilities"] == [
        "supports_normalized_flow",
        "supports_egress_outcome",
        "supports_session_sink_isolation",
        "supports_trace_barrier",
        "supports_carrier_lifecycle",
        "supports_logical_carrier_binding",
        "supports_multi_path_carrier",
        "supports_protocol_snapshot",
    ]
    monkeypatch.setattr(
        environment,
        "_controller_get",
        lambda *args: {
            "version": 1,
            "supports_normalized_flow": True,
            "supports_egress_outcome": True,
            "supports_session_sink_isolation": True,
            "supports_trace_barrier": True,
            "supports_carrier_lifecycle": True,
            "supports_logical_carrier_binding": True,
            "supports_multi_path_carrier": True,
            "supports_protocol_snapshot": True,
        },
    )
    assert environment.check_controller("http://127.0.0.1:9090").code == "CORE_READY"


def test_interface_diagnostics_cover_missing_and_enumeration_failure(monkeypatch):
    monkeypatch.setattr(environment.socket, "if_nameindex", lambda: [(1, "lo"), (2, "eth0")])
    assert environment.check_interface("Meta", role="tun").code == "TUN_INTERFACE_NOT_FOUND"
    assert environment.check_interface("eth0", role="physical").ok is True
    not_configured = environment.check_interface("", role="tun")
    assert not_configured.severity is DiagnosticSeverity.WARNING

    def fail():
        raise OSError("netlink denied")

    monkeypatch.setattr(environment.socket, "if_nameindex", fail)
    assert environment.check_interface("eth0", role="physical").code == (
        "PHYSICAL_INTERFACE_ENUMERATION_FAILED"
    )


def test_capture_tool_diagnostics_cover_missing_permission_and_success(monkeypatch):
    monkeypatch.setattr(environment.shutil, "which", lambda name: None)
    assert environment.check_capture_tool().code == "CAPTURE_TOOL_NOT_FOUND"

    monkeypatch.setattr(environment.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        environment.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 1, stdout="", stderr="Permission denied"
        ),
    )
    assert environment.check_capture_tool().code == "CAPTURE_PERMISSION_DENIED"

    monkeypatch.setattr(
        environment.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, stdout="1. eth0", stderr=""
        ),
    )
    assert environment.check_capture_tool().code == "CAPTURE_TOOL_READY"


def test_chrome_diagnostic_requires_executable(tmp_path):
    chrome = tmp_path / "chromium"
    chrome.write_text("#!/bin/sh\n", encoding="utf-8")
    assert environment.check_chrome(str(chrome)).code == "CHROME_NOT_EXECUTABLE"
    chrome.chmod(0o700)
    assert environment.check_chrome(str(chrome)).code == "CHROME_READY"


def test_output_directory_diagnostics_cover_relative_missing_and_permissions(
    tmp_path, monkeypatch
):
    assert environment.check_output_directory("relative").code == (
        "OUTPUT_DIRECTORY_NOT_ABSOLUTE"
    )
    future = tmp_path / "future"
    warning = environment.check_output_directory(str(future))
    assert warning.code == "OUTPUT_DIRECTORY_WILL_CREATE"
    assert warning.severity is DiagnosticSeverity.WARNING
    monkeypatch.setattr(environment.os, "access", lambda *args: False)
    assert environment.check_output_directory(str(tmp_path)).code == (
        "OUTPUT_DIRECTORY_NOT_WRITABLE"
    )


def test_disk_space_diagnostic_reports_low_and_ready(tmp_path, monkeypatch):
    usage_type = type(shutil.disk_usage(tmp_path))
    monkeypatch.setattr(
        environment.shutil,
        "disk_usage",
        lambda path: usage_type(total=1000, used=900, free=100),
    )
    assert environment.check_disk_space(str(tmp_path), 200).code == "DISK_SPACE_LOW"
    assert environment.check_disk_space(str(tmp_path), 50).code == "DISK_SPACE_READY"


def test_environment_report_keeps_all_checks_and_stable_fields(tmp_path, monkeypatch):
    monkeypatch.setattr(
        environment,
        "_controller_get",
        lambda *args: {
            "supports_normalized_flow": True,
            "supports_egress_outcome": True,
            "supports_session_sink_isolation": True,
            "supports_trace_barrier": True,
            "supports_carrier_lifecycle": True,
            "supports_logical_carrier_binding": True,
            "supports_multi_path_carrier": True,
            "supports_protocol_snapshot": True,
        },
    )
    monkeypatch.setattr(
        environment.socket,
        "if_nameindex",
        lambda: [(1, "Meta"), (2, "eth0")],
    )
    monkeypatch.setattr(environment.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        environment.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "", ""),
    )
    monkeypatch.setattr(environment.os, "access", lambda *args: True)
    monkeypatch.setattr(environment.Path, "is_file", lambda self: True)
    report = diagnose_environment(EnvironmentSpec(
        controller_endpoint="unix:///tmp/mihomo.sock",
        tun_interface="Meta",
        physical_interface="eth0",
        chrome_binary="chromium",
        output_root=str(tmp_path),
        min_free_bytes=0,
    ))
    payload = report.to_dict()
    assert payload["ok"] is True
    assert len(payload["checks"]) == 7
    for check in payload["checks"]:
        assert set(check) == {
            "code", "ok", "severity", "message", "remediation", "details"
        }
        assert check["message"]
        assert check["remediation"]
