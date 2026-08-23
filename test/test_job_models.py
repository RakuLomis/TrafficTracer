"""Tests for YAML-independent Complete job models."""

import json
from pathlib import Path

import pytest

from traffictracer.contracts import ValidationError
from traffictracer.jobs.models import (
    AnalysisJobOptions,
    AnalysisJobSpec,
    CaptureInterfaces,
    CaptureJobOptions,
    CaptureJobResult,
    CaptureJobSpec,
    ControllerSpec,
    JobState,
    ProgressEvent,
    TargetSource,
)
from traffictracer.playback import PlaybackPolicy


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "test" / "fixtures" / "contracts" / "job-valid.json"
ANALYSIS_FIXTURE = (
    ROOT / "test" / "fixtures" / "contracts" / "job-valid-analysis.json"
)


def _fixture() -> dict:
    with FIXTURE.open(encoding="utf-8") as stream:
        return json.load(stream)


def test_capture_job_round_trips_the_contract_fixture():
    payload = _fixture()
    spec = CaptureJobSpec.from_dict(payload)
    assert spec.to_dict() == payload
    assert spec.interfaces == CaptureInterfaces(tun="Meta", physical="eth0")
    assert spec.controller.secret == "fixture-only-secret"


def test_analysis_job_round_trips_the_contract_fixture():
    with ANALYSIS_FIXTURE.open(encoding="utf-8") as stream:
        payload = json.load(stream)
    spec = AnalysisJobSpec.from_dict(payload)
    assert spec.to_dict() == payload
    assert spec.options == AnalysisJobOptions(
        split_pcaps=True,
        pcap_split_mode="unique_connections",
        write_flow_index=True,
        overwrite=False,
    )


def test_legacy_analysis_split_boolean_normalizes_to_explicit_mode():
    with ANALYSIS_FIXTURE.open(encoding="utf-8") as stream:
        payload = json.load(stream)
    payload["options"].pop("pcap_split_mode")
    payload["options"]["split_pcaps"] = False
    spec = AnalysisJobSpec.from_dict(payload)
    assert spec.options.pcap_split_mode == "none"


def test_capture_job_can_be_constructed_without_yaml():
    spec = CaptureJobSpec(
        job_id="2f746e31-d62a-4e1c-a919-3f88ecde31c2",
        url="https://example.com/",
        domain="example.com",
        duration_seconds=10,
        network="tcp",
        interfaces=CaptureInterfaces(tun="Meta", physical="eth0"),
        output_root="/tmp/traffictracer",
        chrome_binary="/usr/bin/chromium",
        controller=ControllerSpec(endpoint="unix:///tmp/mihomo.sock"),
    )
    payload = spec.to_dict()
    assert payload["kind"] == "capture"
    assert payload["schema_version"] == 2
    assert payload["options"] == CaptureJobOptions().to_dict()
    assert "secret" not in payload["controller"]


def test_capture_options_reject_unknown_pcap_split_mode():
    with pytest.raises(ValueError, match="pcap_split_mode"):
        CaptureJobOptions(pcap_split_mode="compressed")


def test_capture_options_reject_unknown_cache_mode():
    with pytest.raises(ValueError, match="cache_mode"):
        CaptureJobOptions(cache_mode="stale")



def test_capture_options_reject_unknown_proxy_protocol_mode():
    with pytest.raises(ValueError, match="proxy_protocol_mode"):
        CaptureJobOptions(proxy_protocol_mode="guess")

def test_capture_job_round_trips_optional_playback_policy():
    payload = _fixture()
    payload["url"] = "https://www.youtube.com/watch?v=example"
    payload["domain"] = "youtube.com"
    payload["duration_seconds"] = 35
    payload["playback"] = {
        "provider": "youtube",
        "ad_policy": "click_visible_skip",
        "desired_primary_seconds": 25,
    }
    spec = CaptureJobSpec.from_dict(payload)
    assert spec.playback == PlaybackPolicy(
        "youtube", "click_visible_skip", 25,
    )
    assert spec.to_dict() == payload


def test_playback_policy_requires_cdp_and_fits_capture_window():
    common = dict(
        job_id="2f746e31-d62a-4e1c-a919-3f88ecde31c2",
        url="https://www.youtube.com/watch?v=example",
        domain="youtube.com",
        duration_seconds=35,
        network="all",
        interfaces=CaptureInterfaces("Meta", "eth0"),
        output_root="/tmp/traffictracer",
        chrome_binary="/usr/bin/chromium",
        controller=ControllerSpec("unix:///tmp/mihomo.sock"),
        playback=PlaybackPolicy("youtube", desired_primary_seconds=25),
    )
    with pytest.raises(ValueError, match="requires CDP"):
        CaptureJobSpec(
            **common,
            options=CaptureJobOptions(collect_cdp=False),
        )
    with pytest.raises(ValueError, match="cannot exceed"):
        CaptureJobSpec(**{**common, "duration_seconds": 20})


def test_capture_job_serializes_config_target_provenance():
    source = TargetSource(
        mode="config",
        config_path="/tmp/sites.yaml",
        config_sha256="a" * 64,
        target_index=2,
    )
    assert source.to_dict() == {
        "mode": "config",
        "config_path": "/tmp/sites.yaml",
        "config_sha256": "a" * 64,
        "target_index": 2,
    }


def test_invalid_capture_job_is_rejected_at_serialization_boundary():
    spec = CaptureJobSpec(
        job_id="2f746e31-d62a-4e1c-a919-3f88ecde31c2",
        url="https://example.com/",
        domain="example.com",
        duration_seconds=0,
        network="icmp",
        interfaces=CaptureInterfaces(tun="Meta", physical="eth0"),
        output_root="relative",
        chrome_binary="/usr/bin/chromium",
        controller=ControllerSpec(endpoint="http://127.0.0.1:9090"),
    )
    with pytest.raises(ValidationError):
        spec.to_dict()


def test_job_state_values_and_terminal_property_are_stable():
    assert [state.value for state in JobState] == [
        "created",
        "preparing",
        "capturing",
        "analyzing",
        "completed",
        "failed",
        "cancelled",
        "interrupted",
    ]
    assert not JobState.CAPTURING.terminal
    assert JobState.COMPLETED.terminal


def test_progress_event_serializes_enum_and_utc_timestamp():
    event = ProgressEvent(
        job_id="job-1",
        state=JobState.CAPTURING,
        stage="capture.packets",
        progress=0.25,
        message="capturing",
    ).to_dict()
    assert event["state"] == "capturing"
    assert event["progress"] == 0.25
    assert event["timestamp"].endswith("Z")


def test_capture_result_requires_terminal_state_and_serializes_tuples():
    with pytest.raises(ValueError, match="terminal"):
        CaptureJobResult(job_id="job-1", state=JobState.CAPTURING)
    result = CaptureJobResult(
        job_id="job-1",
        state=JobState.COMPLETED,
        session_id="session-1",
        artifacts=("manifest.json", "analysis/correlation.json"),
    )
    assert result.to_dict()["artifacts"] == ["manifest.json", "analysis/correlation.json"]
