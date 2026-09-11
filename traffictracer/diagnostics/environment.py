"""Independent preflight checks used by the Complete UI and Worker."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import socket
import subprocess

from traffictracer.capture.mihomo import MihomoManager
from traffictracer.process_env import external_process_env

from .models import DiagnosticCheck, DiagnosticReport, DiagnosticSeverity


DEFAULT_MIN_FREE_BYTES = 1 * 1024 * 1024 * 1024
REQUIRED_TRACING_CAPABILITIES = (
    "supports_normalized_flow",
    "supports_egress_outcome",
    "supports_session_sink_isolation",
    "supports_trace_barrier",
    "supports_carrier_lifecycle",
    "supports_logical_carrier_binding",
    "supports_multi_path_carrier",
    "supports_protocol_snapshot",
)


@dataclass(frozen=True)
class EnvironmentSpec:
    controller_endpoint: str
    controller_secret: str = ""
    tun_interface: str = ""
    physical_interface: str = ""
    chrome_binary: str = "google-chrome"
    output_root: str = ""
    min_free_bytes: int = DEFAULT_MIN_FREE_BYTES


def diagnose_environment(spec: EnvironmentSpec) -> DiagnosticReport:
    checks = (
        check_controller(spec.controller_endpoint, spec.controller_secret),
        check_interface(spec.tun_interface, role="tun"),
        check_interface(spec.physical_interface, role="physical"),
        check_capture_tool(),
        check_chrome(spec.chrome_binary),
        check_output_directory(spec.output_root),
        check_disk_space(spec.output_root, spec.min_free_bytes),
    )
    return DiagnosticReport(checks)


def check_controller(endpoint: str, secret: str = "") -> DiagnosticCheck:
    if not endpoint.strip():
        return _failure(
            "CORE_ENDPOINT_MISSING",
            "No Mihomo controller endpoint is configured.",
            "Select the TrafficTracer core and provide its controller endpoint.",
        )
    try:
        capabilities = _controller_get(endpoint, secret, "/experimental/tracing/capabilities")
    except Exception as exc:
        return _failure(
            "CORE_TRACING_UNAVAILABLE",
            f"TrafficTracer capabilities are unavailable: {_safe_error(exc)}",
            "Start mihomo-traffictracer and verify the controller endpoint and secret.",
            endpoint=endpoint,
        )
    missing_capabilities = [
        name
        for name in REQUIRED_TRACING_CAPABILITIES
        if not isinstance(capabilities, dict) or capabilities.get(name) is not True
    ]
    if missing_capabilities:
        return _failure(
            "CORE_CAPABILITY_MISMATCH",
            "The selected core is missing required TrafficTracer capabilities: "
            + ", ".join(missing_capabilities),
            "Select the verge-mihomo-tt core built from the pinned TrafficTracer branch.",
            endpoint=endpoint,
            missing_capabilities=missing_capabilities,
        )
    return _success(
        "CORE_READY",
        "The TrafficTracer Mihomo controller and tracing API are ready.",
        endpoint=endpoint,
        capabilities=capabilities,
    )


def check_interface(name: str, *, role: str) -> DiagnosticCheck:
    normalized = name.strip()
    label = "TUN" if role == "tun" else "Physical"
    if not normalized:
        severity = (
            DiagnosticSeverity.WARNING if role == "tun" else DiagnosticSeverity.ERROR
        )
        return _failure(
            f"{role.upper()}_INTERFACE_NOT_CONFIGURED",
            f"{label} capture interface is not configured.",
            f"Select the {label.lower()} interface in TrafficTracer settings.",
            severity=severity,
        )
    try:
        available = {interface for _, interface in socket.if_nameindex()}
    except OSError as exc:
        return _failure(
            f"{role.upper()}_INTERFACE_ENUMERATION_FAILED",
            f"Unable to enumerate network interfaces: {_safe_error(exc)}",
            "Check OS network permissions and retry diagnostics.",
        )
    if normalized not in available:
        return _failure(
            f"{role.upper()}_INTERFACE_NOT_FOUND",
            f"{label} interface '{normalized}' does not exist.",
            "Refresh interfaces after enabling TUN or reconnecting the network.",
            interface=normalized,
        )
    return _success(
        f"{role.upper()}_INTERFACE_READY",
        f"{label} interface '{normalized}' is available.",
        interface=normalized,
    )


def check_capture_tool() -> DiagnosticCheck:
    tshark = shutil.which("tshark")
    dumpcap = shutil.which("dumpcap")
    if not tshark or not dumpcap:
        return _failure(
            "CAPTURE_TOOL_NOT_FOUND",
            "tshark and dumpcap are required for packet capture.",
            "Install Wireshark CLI tools and ensure tshark/dumpcap are on PATH.",
        )
    try:
        completed = subprocess.run(
            [dumpcap, "-D"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3,
            check=False,
            env=external_process_env(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return _failure(
            "CAPTURE_TOOL_CHECK_FAILED",
            f"Unable to execute dumpcap: {_safe_error(exc)}",
            "Verify the dumpcap executable and its Linux capabilities.",
        )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        lowered = detail.lower()
        permission = any(
            marker in lowered
            for marker in ("permission denied", "operation not permitted", "cap_net_raw")
        )
        return _failure(
            "CAPTURE_PERMISSION_DENIED" if permission else "CAPTURE_TOOL_UNAVAILABLE",
            detail or f"dumpcap exited with code {completed.returncode}.",
            (
                "Grant dumpcap capture capabilities or add the user to the wireshark group."
                if permission
                else "Run dumpcap -D in a terminal and fix the reported error."
            ),
        )
    return _success(
        "CAPTURE_TOOL_READY",
        "tshark and dumpcap are installed and can enumerate interfaces.",
        tshark=tshark,
        dumpcap=dumpcap,
    )


def check_chrome(binary: str) -> DiagnosticCheck:
    configured = binary.strip()
    resolved = ""
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.is_absolute() or "/" in configured:
            resolved = str(candidate.resolve(strict=False))
        else:
            resolved = shutil.which(configured) or ""
    if not resolved or not Path(resolved).is_file() or not os.access(resolved, os.X_OK):
        return _failure(
            "CHROME_NOT_EXECUTABLE",
            "The configured Chrome/Chromium executable is unavailable.",
            "Select an executable Chrome or Chromium binary.",
            configured=configured,
        )
    return _success(
        "CHROME_READY",
        "Chrome/Chromium is available for CDP capture.",
        path=resolved,
    )


def check_output_directory(output_root: str) -> DiagnosticCheck:
    if not output_root.strip():
        return _failure(
            "OUTPUT_DIRECTORY_MISSING",
            "No output directory is configured.",
            "Choose an absolute directory for TrafficTracer Sessions.",
        )
    path = Path(output_root).expanduser()
    if not path.is_absolute():
        return _failure(
            "OUTPUT_DIRECTORY_NOT_ABSOLUTE",
            "The output directory must be an absolute path.",
            "Choose the output directory through the folder picker.",
            path=str(path),
        )
    if path.exists() and not path.is_dir():
        return _failure(
            "OUTPUT_DIRECTORY_INVALID",
            "The configured output path is not a directory.",
            "Choose a directory instead of a file.",
            path=str(path),
        )
    writable_target = path if path.exists() else _nearest_existing_parent(path)
    if writable_target is None or not os.access(writable_target, os.W_OK | os.X_OK):
        return _failure(
            "OUTPUT_DIRECTORY_NOT_WRITABLE",
            "The output directory cannot be created or written.",
            "Choose a writable directory or correct its ownership and permissions.",
            path=str(path),
        )
    if not path.exists():
        return _failure(
            "OUTPUT_DIRECTORY_WILL_CREATE",
            "The output directory does not exist yet and will be created.",
            "No action is required, or create the directory now to verify permissions.",
            severity=DiagnosticSeverity.WARNING,
            path=str(path),
        )
    return _success(
        "OUTPUT_DIRECTORY_READY",
        "The Session output directory is writable.",
        path=str(path),
    )


def check_disk_space(output_root: str, min_free_bytes: int) -> DiagnosticCheck:
    if min_free_bytes < 0:
        return _failure(
            "DISK_THRESHOLD_INVALID",
            "The minimum free-space threshold is invalid.",
            "Configure a non-negative minimum free-space threshold.",
        )
    path = Path(output_root).expanduser() if output_root.strip() else Path.cwd()
    target = path if path.exists() else _nearest_existing_parent(path)
    if target is None:
        return _failure(
            "DISK_SPACE_UNAVAILABLE",
            "No existing parent is available for the output directory.",
            "Choose an output directory on a mounted filesystem.",
        )
    try:
        usage = shutil.disk_usage(target)
    except OSError as exc:
        return _failure(
            "DISK_SPACE_UNAVAILABLE",
            f"Unable to inspect free disk space: {_safe_error(exc)}",
            "Verify that the output filesystem is mounted and accessible.",
        )
    if usage.free < min_free_bytes:
        return _failure(
            "DISK_SPACE_LOW",
            f"Only {usage.free} bytes are free for capture artifacts.",
            "Free disk space or choose a different output directory.",
            free_bytes=usage.free,
            required_bytes=min_free_bytes,
        )
    return _success(
        "DISK_SPACE_READY",
        "The output filesystem has sufficient free space.",
        free_bytes=usage.free,
        required_bytes=min_free_bytes,
    )


def _controller_get(endpoint: str, secret: str, path: str) -> dict:
    manager = MihomoManager("", "", endpoint, secret)
    return manager._api_request("GET", path, timeout=3)


def _nearest_existing_parent(path: Path) -> Path | None:
    current = path
    while not current.exists() and current != current.parent:
        current = current.parent
    return current if current.exists() else None


def _safe_error(error: Exception) -> str:
    message = str(error).strip()
    return message or error.__class__.__name__


def _success(code: str, message: str, **details) -> DiagnosticCheck:
    return DiagnosticCheck(
        code=code,
        ok=True,
        severity=DiagnosticSeverity.INFO,
        message=message,
        remediation="No action required.",
        details=details,
    )


def _failure(
    code: str,
    message: str,
    remediation: str,
    *,
    severity: DiagnosticSeverity = DiagnosticSeverity.ERROR,
    **details,
) -> DiagnosticCheck:
    return DiagnosticCheck(
        code=code,
        ok=False,
        severity=severity,
        message=message,
        remediation=remediation,
        details=details,
    )
