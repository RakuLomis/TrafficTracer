"""Tests for browser requests that do not require proxy transport."""

from traffictracer.analyze.request_observation import (
    request_can_have_transport,
    request_network_observation,
)
from traffictracer.models import AttributedRequest


def _request(url: str, **values) -> AttributedRequest:
    request = AttributedRequest(
        request_id="1.1",
        target_id="target",
        frame_id="frame",
        url=url,
        resource_type="Other",
        timestamp=1.0,
    )
    for name, value in values.items():
        setattr(request, name, value)
    return request


def test_loopback_request_is_local_even_when_it_fails_before_socket():
    request = _request(
        "http://127.0.0.1:16422/client",
        failed=True,
        failure_reason="net::ERR_CONNECTION_REFUSED",
    )

    assert request_network_observation(request) == (
        "local_endpoint",
        ["cdp_local_endpoint"],
    )
    assert not request_can_have_transport(request)


def test_remote_failure_without_socket_is_not_transport_eligible():
    request = _request(
        "https://unreachable.example/",
        failed=True,
        failure_reason="net::ERR_NAME_NOT_RESOLVED",
    )

    observation, evidence = request_network_observation(request)

    assert observation == "failed_before_socket"
    assert "cdp_transport_endpoint_absent" in evidence
    assert not request_can_have_transport(request)


def test_request_without_response_or_completion_is_not_dispatched():
    request = _request("https://telemetry.example/ping")

    observation, evidence = request_network_observation(request)

    assert observation == "not_dispatched"
    assert "cdp_completion_absent" in evidence
    assert not request_can_have_transport(request)


def test_response_endpoint_remains_network_eligible():
    request = _request(
        "https://example.com/",
        response_status=200,
        remote_ip="198.18.0.2",
        remote_port=443,
    )

    assert request_network_observation(request)[0] == "network"
    assert request_can_have_transport(request)
