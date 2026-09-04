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


def test_http_error_followed_by_same_frame_success_is_recovered_degradation():
    url = "https://www.zhihu.com/question/fixture"
    result = navigation_outcome(_cdp(url, [
        _document(url, 403),
        _document(url, 200, timestamp=2),
    ]))

    assert result["state"] == "degraded"
    assert result["reason"] == "MAIN_DOCUMENT_HTTP_ERROR_RECOVERED"
    assert result["status_chain"] == [403, 200]
    assert result["recovered"] is True


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
