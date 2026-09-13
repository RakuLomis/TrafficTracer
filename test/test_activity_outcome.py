"""Regression coverage for evidence-backed page activity outcomes."""

from traffictracer.analyze.activity import (
    combine_activity_outcome,
    navigation_outcome,
    resource_health,
)


def _document(url, status, *, timestamp=1, frame="MAIN", target="PAGE", **extra):
    return {
        "url": url,
        "resource_type": "Document",
        "response_status": status,
        "timestamp": timestamp,
        "frame_id": frame,
        "target_id": target,
        "failed": False,
        **extra,
    }


def _cdp(url, requests, **navigation):
    return {
        "visit_url": url,
        "requests": requests,
        "metadata": {
            "navigation": {
                "url": url,
                "status": "loaded",
                **navigation,
            }
        },
    }


def test_final_main_document_404_is_application_failure():
    result = navigation_outcome(_cdp(
        "https://github.com/private/repository",
        [_document("https://github.com/private/repository", 404)],
    ))

    assert result["state"] == "failed"
    assert result["reason"] == "MAIN_DOCUMENT_HTTP_ERROR"
    assert result["final_status"] == 404
    assert result["final_url"] == "https://github.com/private/repository"

def test_missing_cdp_is_not_misreported_as_page_failure():
    navigation = navigation_outcome({})
    resources = resource_health({}, navigation)
    result = combine_activity_outcome(navigation, resources, None)

    assert navigation["state"] == "not_applicable"
    assert resources["state"] == "not_applicable"
    assert result["state"] == "not_applicable"




def test_auxiliary_iframe_401_does_not_override_main_document_success():
    url = "https://www.youtube.com/watch?v=fixture"
    result = navigation_outcome(_cdp(url, [
        _document(url, 200),
        _document(
            "https://accounts.google.com/ServiceLogin",
            401,
            timestamp=2,
            frame="IFRAME",
        ),
    ]))

    assert result["state"] == "passed"
    assert result["status_chain"] == [200]
    assert result["final_status"] == 200


def test_http_error_followed_by_same_frame_success_is_passed_recovery():
    url = "https://www.zhihu.com/question/fixture"
    result = navigation_outcome(_cdp(url, [
        _document(url, 403),
        _document(url, 200, timestamp=2),
    ]))

    assert result["state"] == "passed"
    assert result["reason"] is None
    assert result["status_chain"] == [403, 200]
    assert result["recovered"] is True
    assert result["recovery"] == {
        "observed": True, "kind": "http_status_recovered",
        "intermediate_statuses": [403], "final_status": 200,
    }


def test_fragment_url_matches_network_document_without_fragment():
    requested = "https://www.openstreetmap.org/#map=13/32.0603/118.7969"
    result = navigation_outcome(_cdp(
        requested,
        [_document("https://www.openstreetmap.org/", 200)],
    ))

    assert result["state"] == "passed"
    assert result["final_status"] == 200


def test_redirect_chain_uses_same_main_frame_and_final_response():
    requested = "https://www.bing.com/search?q=fixture"
    final = "https://cn.bing.com/search?q=fixture"
    result = navigation_outcome(_cdp(requested, [
        _document(requested, 302),
        _document(final, 200, timestamp=2),
        _document(
            "https://login.live.com/authorize",
            401,
            timestamp=3,
            frame="AUTH",
        ),
    ]))

    assert result["state"] == "passed"
    assert result["status_chain"] == [302, 200]
    assert result["final_url"] == final


def test_loaded_after_command_timeout_is_explicit_recovered_degradation():
    url = "https://arxiv.org/abs/fixture"
    result = navigation_outcome(_cdp(
        url,
        [_document(url, 200)],
        status="loaded_after_command_timeout",
    ))

    assert result["state"] == "degraded"
    assert result["reason"] == "NAVIGATION_TIMEOUT_RECOVERED"
    assert result["recovered"] is True


def test_main_document_2xx_is_sufficient_for_spa_without_load_event():
    url = "https://example.test/app"
    result = navigation_outcome(_cdp(
        url,
        [_document(url, 200)],
        status="load_event_timeout",
    ))

    assert result["state"] == "passed"
    assert result["reason"] is None
    assert result["load_event_observed"] is False
    assert result["completion_evidence"] == "main_document_2xx_without_load_event"


def test_navigation_certificate_error_is_typed():
    url = "https://www.rottentomatoes.com/m/interstellar_2014"
    result = navigation_outcome(_cdp(
        url, [], error_text="net::ERR_CERT_COMMON_NAME_INVALID",
    ))

    assert result["state"] == "failed"
    assert result["reason"] == "MAIN_DOCUMENT_TLS_ERROR"
    assert result["failure_class"] == "tls_certificate"


def test_transient_navigation_error_with_same_loaded_document_is_recovered():
    url = "https://v.qq.com/"
    loader = "main-loader"
    result = navigation_outcome(_cdp(
        url,
        [_document(url, 200, loader_id=loader)],
        target_id="PAGE",
        frame_id="MAIN",
        loader_id=loader,
        error_text="net::ERR_CERT_VERIFIER_CHANGED",
    ))

    assert result["state"] == "passed"
    assert result["reason"] is None
    assert result["recovered"] is True
    assert result["origin"] is None
    assert result["recovery"] == {
        "observed": True,
        "kind": "navigation_error_recovered",
        "intermediate_error": "net::ERR_CERT_VERIFIER_CHANGED",
        "final_status": 200,
        "loader_id": loader,
    }


def test_iframe_success_does_not_recover_main_navigation_error():
    url = "https://v.qq.com/"
    result = navigation_outcome(_cdp(
        url,
        [_document(
            "https://accounts.example.test/",
            200,
            frame="IFRAME",
            target="PAGE",
            loader_id="iframe-loader",
        )],
        target_id="PAGE",
        frame_id="MAIN",
        loader_id="main-loader",
        error_text="net::ERR_CERT_VERIFIER_CHANGED",
    ))

    assert result["state"] == "failed"
    assert result["reason"] == "MAIN_DOCUMENT_TLS_ERROR"
    assert result["origin"] == "local_runtime"
    assert result["retryable"] is True


def test_different_loader_does_not_recover_navigation_error():
    url = "https://v.qq.com/"
    result = navigation_outcome(_cdp(
        url,
        [_document(url, 200, loader_id="replacement-loader")],
        target_id="PAGE",
        frame_id="MAIN",
        loader_id="failed-loader",
        error_text="net::ERR_CERT_VERIFIER_CHANGED",
    ))

    assert result["state"] == "failed"
    assert result["reason"] == "MAIN_DOCUMENT_TLS_ERROR"
    assert result["final_status"] == 200
    assert result["origin"] == "local_runtime"
    assert result["retryable"] is True


def test_deterministic_certificate_error_remains_non_retryable():
    url = "https://invalid.example.test/"
    result = navigation_outcome(_cdp(
        url, [], error_text="net::ERR_CERT_COMMON_NAME_INVALID",
    ))

    assert result["state"] == "failed"
    assert result["origin"] == "remote_network"
    assert result["retryable"] is False


def test_failed_main_document_dns_error_is_typed():
    url = "https://unreachable.example.test/"
    result = navigation_outcome(_cdp(url, [
        _document(
            url, 0, failed=True,
            failure_reason="net::ERR_NAME_NOT_RESOLVED",
        ),
    ]))

    assert result["state"] == "failed"
    assert result["reason"] == "MAIN_DOCUMENT_DNS_ERROR"
    assert result["failure_class"] == "dns"


def test_systemic_unrecovered_critical_resource_failures_are_degraded():
    url = "https://vimeo.com/fixture"
    requests = [_document(url, 200)]
    requests.extend({
        "url": f"https://cdn.example/chunk-{index}.js",
        "resource_type": "Script",
        "target_id": "PAGE",
        "failed": index < 5,
        "failure_reason": (
            "net::ERR_CERT_VERIFIER_CHANGED" if index < 5 else ""
        ),
    } for index in range(10))
    cdp = _cdp(url, requests)
    navigation = navigation_outcome(cdp)
    health = resource_health(cdp, navigation)

    assert health["state"] == "degraded"
    assert health["reason"] == "CRITICAL_RESOURCE_FAILURE_BURST"
    assert health["critical_requests"] == 10
    assert health["unrecovered_failures"] == 5
    assert health["failure_ratio"] == 0.5


def test_loopback_probe_failures_are_retained_but_not_remote_degradation():
    url = "https://www.iqiyi.com/"
    requests = [_document(url, 200)]
    for port in (16422, 16423, 16424):
        requests.append({
            "url": f"http://127.0.0.1:{port}/client.js",
            "resource_type": "Script",
            "target_id": "PAGE",
            "failed": True,
            "failure_reason": "net::ERR_CONNECTION_REFUSED",
        })
    health = resource_health(_cdp(url, requests), navigation_outcome(_cdp(url, requests)))

    assert health["state"] == "passed"
    assert health["critical_requests"] == 0
    assert health["observed_critical_requests"] == 3
    assert health["unrecovered_failures"] == 0
    assert health["local_observations"]["unrecovered_failures"] == 3
    assert health["local_observations"]["failure_reasons"] == {
        "net::ERR_CONNECTION_REFUSED": 3,
    }


def test_private_lan_resource_is_not_excluded_as_loopback():
    url = "https://example.com/"
    requests = [_document(url, 200)] + [{
        "url": f"http://192.168.5.10/chunk-{index}.js",
        "resource_type": "Script",
        "target_id": "PAGE",
        "failed": True,
        "failure_reason": "net::ERR_CONNECTION_REFUSED",
    } for index in range(3)]
    cdp = _cdp(url, requests)
    health = resource_health(cdp, navigation_outcome(cdp))

    assert health["state"] == "degraded"
    assert health["critical_requests"] == 3
    assert health["failure_origins"] == {"remote_network": 3}
    assert health["retryable"] is True


def test_browser_policy_failures_are_observations_not_remote_failures():
    url = "https://example.com/"
    requests = [_document(url, 200)] + [{
        "url": f"https://cdn.example/chunk-{index}.js",
        "resource_type": "Script",
        "target_id": "PAGE",
        "failed": True,
        "failure_reason": "net::ERR_BLOCKED_BY_ORB",
    } for index in range(3)]
    cdp = _cdp(url, requests)
    health = resource_health(cdp, navigation_outcome(cdp))

    assert health["state"] == "passed"
    assert health["critical_requests"] == 0
    assert health["browser_policy_observations"]["unrecovered_failures"] == 3


def test_remote_transient_resource_burst_is_typed_and_retryable():
    url = "https://news.qq.com/"
    requests = [_document(url, 200)] + [{
        "url": f"https://mat1.gtimg.com/chunk-{index}.js",
        "resource_type": "Script",
        "target_id": "PAGE",
        "failed": True,
        "failure_reason": "net::ERR_CONNECTION_CLOSED",
    } for index in range(3)]
    cdp = _cdp(url, requests)
    health = resource_health(cdp, navigation_outcome(cdp))

    assert health["state"] == "degraded"
    assert health["origin"] == "remote_network"
    assert health["retryable"] is True
    assert health["failed_hosts"] == {"mat1.gtimg.com": 3}


def test_tls_resource_burst_is_not_automatically_retried():
    url = "https://example.com/"
    requests = [_document(url, 200)] + [{
        "url": f"https://cdn.example/chunk-{index}.js",
        "resource_type": "Script",
        "target_id": "PAGE",
        "failed": True,
        "failure_reason": "net::ERR_CERT_COMMON_NAME_INVALID",
    } for index in range(3)]
    cdp = _cdp(url, requests)
    health = resource_health(cdp, navigation_outcome(cdp))

    assert health["state"] == "degraded"
    assert health["origin"] == "evidence_limit"
    assert health["retryable"] is False


def test_critical_http_errors_count_as_resource_failures():
    url = "https://example.com/"
    requests = [_document(url, 200)]
    requests.extend({
        "url": f"https://example.com/chunk-{index}.js",
        "resource_type": "Script",
        "target_id": "PAGE",
        "failed": False,
        "response_status": 503 if index < 3 else 200,
    } for index in range(4))
    cdp = _cdp(url, requests)

    health = resource_health(cdp, navigation_outcome(cdp))

    assert health["state"] == "degraded"
    assert health["unrecovered_failures"] == 3
    assert health["failure_ratio"] == 0.75
    assert health["failure_reasons"] == {"HTTP_503": 3}


def test_later_success_for_same_resource_is_not_unrecovered():
    url = "https://example.com/"
    script = "https://example.com/app.js"
    cdp = _cdp(url, [
        _document(url, 200),
        {
            "url": script,
            "resource_type": "Script",
            "target_id": "PAGE",
            "failed": True,
            "failure_reason": "net::ERR_CONNECTION_CLOSED",
        },
        {
            "url": script,
            "resource_type": "Script",
            "target_id": "PAGE",
            "failed": False,
        },
    ])
    health = resource_health(cdp, navigation_outcome(cdp))

    assert health["state"] == "passed"
    assert health["unrecovered_failures"] == 0
    assert health["recovered_failures"] == 1


def test_activity_combines_navigation_resources_and_playback():
    navigation = {
        "state": "passed", "reason": None,
        "requested_url": "https://youtube.test/watch",
        "final_url": "https://youtube.test/watch", "final_status": 200,
    }
    resources = {
        "state": "passed", "reason": None,
    }
    playback = {
        "kind": "youtube_playback",
        "state": "degraded",
        "reason": "PRIMARY_DURATION_BELOW_TARGET",
        "primary_content_seconds": 23.9,
        "desired_primary_seconds": 25,
    }

    result = combine_activity_outcome(navigation, resources, playback)

    assert result["kind"] == "youtube_playback"
    assert result["state"] == "degraded"
    assert result["reason"] == "PRIMARY_DURATION_BELOW_TARGET"
    assert result["final_status"] == 200
