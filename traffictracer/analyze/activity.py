"""Evidence-backed page navigation and application outcome classification."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from urllib.parse import urldefrag, urlsplit

from traffictracer.analyze.request_observation import request_targets_loopback

_CRITICAL_RESOURCE_TYPES = frozenset({"script", "stylesheet", "font"})
_BROWSER_POLICY_MARKERS = ("ERR_ABORTED", "ERR_BLOCKED_BY_", "BLOCKED_REASON")
_RECOVERED_NAVIGATION_STATES = frozenset({
    "loaded_after_command_timeout",
})
_UNRESOLVED_NAVIGATION_STATES = frozenset({
    "started",
    "command_timeout",
    "command_and_load_timeout",
    "load_event_timeout",
})


def session_activity_outcomes(
    session_dir: str | Path,
    playback_outcome: dict | None = None,
) -> tuple[dict, dict, dict]:
    """Return navigation, resource-health, and effective activity outcomes."""
    cdp = _read_json(Path(session_dir) / "raw" / "cdp.json")
    navigation = navigation_outcome(cdp)
    resources = resource_health(cdp, navigation)
    activity = combine_activity_outcome(
        navigation,
        resources,
        playback_outcome,
    )
    return navigation, resources, activity


def navigation_outcome(cdp: dict) -> dict:
    """Classify the top-level document without using iframe response failures."""
    visit_url = str(cdp.get("visit_url") or "")
    metadata = cdp.get("metadata")
    navigation = (
        metadata.get("navigation", {})
        if isinstance(metadata, dict) else {}
    )
    if not isinstance(navigation, dict):
        navigation = {}
    requested_url = str(
        navigation.get("requested_url")
        or navigation.get("url")
        or visit_url
    )
    base = {
        "requested_url": requested_url,
        "final_url": None,
        "final_status": None,
        "status_chain": [],
        "navigation_status": navigation.get("status"),
        "main_target_id": navigation.get("target_id"),
        "main_frame_id": navigation.get("frame_id"),
        "main_loader_id": navigation.get("loader_id"),
        "main_document_requests": 0,
        "recovered": False,
        "completion_evidence": None,
        "failure_class": None,
        "origin": None,
        "retryable": False,
    }
    if not cdp:
        return _outcome(base, "not_applicable", "CDP_EVIDENCE_UNAVAILABLE", origin="evidence_limit")
    error_text = str(navigation.get("error_text") or "")
    if error_text:
        base["error_text"] = error_text

    documents = [
        item for item in cdp.get("requests", [])
        if isinstance(item, dict)
        and str(item.get("resource_type", "")).lower() == "document"
    ]
    target_url = _normalized_url(requested_url or visit_url)
    exact = [
        item for item in documents
        if _normalized_url(item.get("url")) == target_url
    ]
    seed = min(exact, key=_request_order) if exact else None
    frame_id = str(navigation.get("frame_id") or "")
    target_id = str(navigation.get("target_id") or "")
    if seed is not None:
        frame_id = frame_id or str(seed.get("frame_id") or "")
        target_id = target_id or str(seed.get("target_id") or "")
    base["main_frame_id"] = frame_id or None
    base["main_target_id"] = target_id or None

    primary = documents
    if target_id:
        primary = [
            item for item in primary
            if str(item.get("target_id") or "") == target_id
        ]
    if frame_id:
        primary = [
            item for item in primary
            if str(item.get("frame_id") or "") == frame_id
        ]
    elif exact:
        primary = exact
    if not primary and exact:
        primary = exact
    primary.sort(key=_request_order)
    base["main_document_requests"] = len(primary)
    if not primary:
        if error_text:
            base["failure_class"] = _network_failure_class(error_text)
            return _outcome(
                base, "failed", _main_document_network_reason(base["failure_class"]),
                origin=_navigation_error_origin(error_text),
                retryable=_navigation_error_retryable(error_text),
            )
        return _outcome(
            base, "indeterminate", "MAIN_DOCUMENT_NOT_OBSERVED",
            origin="evidence_limit", retryable=True,
        )

    status_chain = [
        status for item in primary
        if (status := _status(item.get("response_status"))) is not None
        and status > 0
    ]
    final = primary[-1]
    final_status = _status(final.get("response_status"))
    final_url = str(final.get("url") or "") or None
    explicit_final_url = str(navigation.get("final_url") or "")
    if explicit_final_url and explicit_final_url != "about:blank":
        final_url = explicit_final_url
    base["final_url"] = final_url
    base["final_status"] = final_status
    base["status_chain"] = status_chain
    base["main_loader_id"] = (
        str(navigation.get("loader_id") or final.get("loader_id") or "")
        or None
    )
    base["failure_reason"] = str(final.get("failure_reason") or "") or None

    nav_status = str(navigation.get("status") or "")
    base["load_event_observed"] = nav_status in {"loaded", "loaded_after_command_timeout"}
    navigation_loader_id = str(navigation.get("loader_id") or "")
    final_loader_id = str(final.get("loader_id") or "")
    navigation_error_recovered = bool(
        error_text
        and nav_status == "loaded"
        and final_status is not None
        and 200 <= final_status < 300
        and seed is not None
        and navigation_loader_id
        and final_loader_id == navigation_loader_id
    )
    if error_text and not navigation_error_recovered:
        base["failure_class"] = _network_failure_class(error_text)
        return _outcome(
            base, "failed", _main_document_network_reason(base["failure_class"]),
            origin=_navigation_error_origin(error_text),
            retryable=_navigation_error_retryable(error_text),
        )
    prior_http_error = any(status >= 400 for status in status_chain[:-1])
    if final_status in {408, 429}:
        return _outcome(base, "failed", "MAIN_DOCUMENT_TRANSIENT_HTTP_ERROR", origin="remote_site", retryable=True)
    if final_status is not None and final_status >= 500:
        return _outcome(base, "failed", "MAIN_DOCUMENT_SERVER_ERROR", origin="remote_site", retryable=True)
    if final_status is not None and final_status >= 400:
        return _outcome(base, "failed", "MAIN_DOCUMENT_HTTP_ERROR", origin="remote_site")
    if bool(final.get("failed")) and not final_status:
        base["failure_class"] = _network_failure_class(base["failure_reason"])
        return _outcome(
            base, "failed", _main_document_network_reason(base["failure_class"]),
            origin="remote_network",
            retryable=base["failure_class"] != "tls_certificate",
        )
    if final_status is None or final_status <= 0:
        return _outcome(base, "indeterminate", "MAIN_DOCUMENT_RESPONSE_UNKNOWN", origin="evidence_limit", retryable=True)
    if 300 <= final_status < 400:
        return _outcome(base, "indeterminate", "MAIN_DOCUMENT_REDIRECT_INCOMPLETE", origin="remote_site")
    if 200 <= final_status < 300:
        base["completion_evidence"] = "main_document_2xx"
        if navigation_error_recovered:
            base["recovered"] = True
            base["recovery"] = {
                "observed": True,
                "kind": "navigation_error_recovered",
                "intermediate_error": error_text,
                "final_status": final_status,
                "loader_id": navigation_loader_id,
            }
            # Keep the transient command error as evidence, while treating the
            # same committed loader's completed response as the final outcome.
            return _outcome(base, "passed", None)
        if prior_http_error:
            base["recovered"] = True
            base["recovery"] = {
                "observed": True,
                "kind": "http_status_recovered",
                "intermediate_statuses": [
                    status for status in status_chain[:-1] if status >= 400
                ],
                "final_status": final_status,
            }
            return _outcome(base, "passed", None)
        if nav_status in _RECOVERED_NAVIGATION_STATES:
            base["recovered"] = True
            return _outcome(
                base, "degraded", "NAVIGATION_TIMEOUT_RECOVERED",
                origin="local_runtime",
            )
        if nav_status in _UNRESOLVED_NAVIGATION_STATES:
            # Modern SPAs and long-lived pages may intentionally never publish
            # loadEventFired. A completed top-level 2xx response is stronger
            # page-load evidence than that optional lifecycle signal.
            base["completion_evidence"] = "main_document_2xx_without_load_event"
            return _outcome(base, "passed", None)
        return _outcome(base, "passed", None)
    return _outcome(base, "indeterminate", "MAIN_DOCUMENT_STATUS_UNSUPPORTED")


def resource_health(cdp: dict, navigation: dict) -> dict:
    """Report systemic unrecovered failures of render-critical resources."""
    target_id = str(navigation.get("main_target_id") or "")
    if not cdp:
        return {
            "state": "not_applicable",
            "reason": "CDP_EVIDENCE_UNAVAILABLE",
            "critical_requests": 0,
            "unrecovered_failures": 0,
            "recovered_failures": 0,
            "failure_ratio": 0.0,
            "failure_reasons": {},
            "failure_types": {},
            "failure_origins": {},
            "failed_hosts": {},
            "local_observations": {
                "critical_requests": 0,
                "unrecovered_failures": 0,
                "failure_reasons": {},
                "endpoints": {},
            },
            "origin": "evidence_limit",
            "retryable": False,
            "threshold": {"minimum_failures": 3, "minimum_ratio": 0.20},
        }

    requests = [
        item for item in cdp.get("requests", [])
        if isinstance(item, dict)
        and str(item.get("resource_type", "")).lower()
        in _CRITICAL_RESOURCE_TYPES
        and (
            not target_id
            or str(item.get("target_id") or "") == target_id
        )
    ]
    local_requests = [
        item for item in requests
        if request_targets_loopback(item.get("url"), item.get("remote_ip"))
    ]
    remote_requests = [
        item for item in requests
        if not request_targets_loopback(item.get("url"), item.get("remote_ip"))
    ]
    local_failures = [item for item in local_requests if _request_failed(item)]
    local_reasons = Counter(_request_failure_reason(item) for item in local_failures)
    local_endpoints = Counter(_request_endpoint(item) for item in local_requests)

    policy_failures = [
        item for item in remote_requests
        if _request_failed(item) and _failure_origin(item) == "browser_policy"
    ]
    eligible_requests = [
        item for item in remote_requests
        if item not in policy_failures
    ]
    latest_success: dict[str, int] = {}
    for index, item in enumerate(eligible_requests):
        url = _normalized_url(item.get("url"))
        if url and not _request_failed(item):
            latest_success[url] = index
    failures = []
    recovered = 0
    for index, item in enumerate(eligible_requests):
        if not _request_failed(item):
            continue
        url = _normalized_url(item.get("url"))
        if url and latest_success.get(url, -1) > index:
            recovered += 1
            continue
        failures.append(item)
    total = len(eligible_requests)
    failure_count = len(failures)
    ratio = failure_count / total if total else 0.0
    reasons = Counter(
        _request_failure_reason(item)
        for item in failures
    )
    types = Counter(
        str(item.get("resource_type") or "Other")
        for item in failures
    )
    origins = Counter(_failure_origin(item) for item in failures)
    hosts = Counter(_request_host(item) for item in failures)
    systemic = failure_count >= 3 and ratio >= 0.20
    retryable = systemic and any(
        _failure_retryable(item) for item in failures
    )
    origin = _dominant_origin(origins) if systemic else None
    return {
        "state": "degraded" if systemic else "passed",
        "reason": "CRITICAL_RESOURCE_FAILURE_BURST" if systemic else None,
        "critical_requests": total,
        "observed_critical_requests": len(requests),
        "unrecovered_failures": failure_count,
        "recovered_failures": recovered,
        "failure_ratio": round(ratio, 6),
        "failure_reasons": dict(sorted(reasons.items())),
        "failure_types": dict(sorted(types.items())),
        "failure_origins": dict(sorted(origins.items())),
        "failed_hosts": dict(sorted(hosts.items())),
        "browser_policy_observations": {
            "unrecovered_failures": len(policy_failures),
            "failure_reasons": dict(sorted(Counter(
                _request_failure_reason(item) for item in policy_failures
            ).items())),
        },
        "local_observations": {
            "critical_requests": len(local_requests),
            "unrecovered_failures": len(local_failures),
            "failure_reasons": dict(sorted(local_reasons.items())),
            "endpoints": dict(sorted(local_endpoints.items())),
        },
        "origin": origin,
        "retryable": retryable,
        "threshold": {
            "minimum_failures": 3,
            "minimum_ratio": 0.20,
        },
    }


def combine_activity_outcome(
    navigation: dict,
    resources: dict,
    playback: dict | None,
) -> dict:
    """Combine observable components without claiming unavailable semantics."""
    components = [navigation, resources]
    if isinstance(playback, dict):
        components.append(playback)
    rank = {"passed": 0, "degraded": 1, "indeterminate": 2, "failed": 3}
    applicable = [
        item for item in components
        if item.get("state") != "not_applicable"
    ]
    effective = (
        max(
            applicable,
            key=lambda item: rank.get(str(item.get("state")), 2),
        )
        if applicable else {"state": "not_applicable", "reason": None}
    )
    result = dict(playback) if isinstance(playback, dict) else {}
    result.update({
        "kind": (
            str(playback.get("kind"))
            if isinstance(playback, dict) and playback.get("kind")
            else "page_load"
        ),
        "state": effective.get("state", "indeterminate"),
        "reason": effective.get("reason"),
        "navigation_state": navigation.get("state"),
        "resource_health_state": resources.get("state"),
        "requested_url": navigation.get("requested_url"),
        "final_url": navigation.get("final_url"),
        "final_status": navigation.get("final_status"),
        "origin": effective.get("origin") or _reason_origin(effective.get("reason")),
        "retryable": bool(effective.get("retryable", _reason_retryable(effective.get("reason")))),
        "navigation_recovered": bool(navigation.get("recovered")),
        "local_critical_observations": resources.get("local_observations", {}),
    })
    return result


def _outcome(
    base: dict,
    state: str,
    reason: str | None,
    *,
    origin: str | None = None,
    retryable: bool = False,
) -> dict:
    return {
        **base,
        "state": state,
        "reason": reason,
        "origin": origin,
        "retryable": retryable,
    }


def _normalized_url(value: object) -> str:
    return urldefrag(str(value or ""))[0]


def _request_order(item: dict) -> tuple[float, int]:
    try:
        timestamp = float(item.get("timestamp", 0.0))
    except (TypeError, ValueError):
        timestamp = 0.0
    try:
        redirect_index = int(item.get("redirect_index", 0))
    except (TypeError, ValueError):
        redirect_index = 0
    return timestamp, redirect_index


def _status(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _request_failed(item: dict) -> bool:
    status = _status(item.get("response_status"))
    return bool(item.get("failed")) or (
        status is not None and status >= 400
    )


def _request_failure_reason(item: dict) -> str:
    reason = str(item.get("failure_reason") or "")
    if reason:
        return reason
    status = _status(item.get("response_status"))
    return f"HTTP_{status}" if status is not None else "loading_failed"

def _request_host(item: dict) -> str:
    return (urlsplit(str(item.get("url") or "")).hostname or "unknown").lower()


def _request_endpoint(item: dict) -> str:
    host = _request_host(item)
    port = urlsplit(str(item.get("url") or "")).port
    return f"{host}:{port}" if port is not None else host


def _failure_origin(item: dict) -> str:
    if request_targets_loopback(item.get("url"), item.get("remote_ip")):
        return "local_expected"
    reason = _request_failure_reason(item).upper()
    if any(marker in reason for marker in _BROWSER_POLICY_MARKERS):
        return "browser_policy"
    status = _status(item.get("response_status"))
    if status is not None and status >= 400:
        return "remote_site"
    if _network_failure_class(reason) in {"dns", "timeout", "connectivity"}:
        return "remote_network"
    return "evidence_limit"


def _failure_retryable(item: dict) -> bool:
    origin = _failure_origin(item)
    if origin in {"local_expected", "browser_policy"}:
        return False
    status = _status(item.get("response_status"))
    if status in {408, 429} or (status is not None and status >= 500):
        return True
    failure_class = _network_failure_class(_request_failure_reason(item))
    return failure_class in {"dns", "timeout", "connectivity"}


def _dominant_origin(origins: Counter) -> str | None:
    if not origins:
        return None
    ranked = sorted(origins.items(), key=lambda item: (-item[1], item[0]))
    return ranked[0][0]


def _reason_origin(reason: object) -> str | None:
    value = str(reason or "")
    if value.startswith("MAIN_DOCUMENT_"):
        if value.endswith("HTTP_ERROR") or value.endswith("SERVER_ERROR"):
            return "remote_site"
        if value.endswith(("CONNECTION_ERROR", "DNS_ERROR", "NETWORK_ERROR", "TIMEOUT")):
            return "remote_network"
        if value in {"MAIN_DOCUMENT_NOT_OBSERVED", "MAIN_DOCUMENT_RESPONSE_UNKNOWN"}:
            return "evidence_limit"
    if value.startswith(("PLAYER_", "VIDEO_", "MEDIA_", "PRIMARY_CONTENT_", "PLAYBACK_")):
        return "browser_activity"
    return None


def _reason_retryable(reason: object) -> bool:
    return str(reason or "") in {
        "MAIN_DOCUMENT_CONNECTION_ERROR", "MAIN_DOCUMENT_DNS_ERROR",
        "MAIN_DOCUMENT_NETWORK_ERROR", "MAIN_DOCUMENT_NOT_OBSERVED",
        "MAIN_DOCUMENT_RESPONSE_UNKNOWN", "MAIN_DOCUMENT_SERVER_ERROR",
        "MAIN_DOCUMENT_TIMEOUT", "MAIN_DOCUMENT_TRANSIENT_HTTP_ERROR",
        "PLAYBACK_STATE_UNKNOWN", "PLAYER_NOT_CREATED", "VIDEO_ELEMENT_NOT_CREATED",
        "MEDIA_NOT_READY", "MEDIA_NOT_ADVANCING", "PRIMARY_CONTENT_NOT_OBSERVED",
    }


def _network_failure_class(reason: object) -> str:
    value = str(reason or "").upper()
    if "ERR_CERT_" in value or "SSL_" in value or "TLS_" in value:
        return "tls_certificate"
    if "ERR_NAME_NOT_RESOLVED" in value or "ERR_DNS_" in value:
        return "dns"
    if "ERR_TIMED_OUT" in value or "TIMEOUT" in value:
        return "timeout"
    if any(marker in value for marker in (
        "ERR_CONNECTION_", "ERR_NETWORK_", "ERR_INTERNET_DISCONNECTED",
        "ERR_ADDRESS_UNREACHABLE",
    )):
        return "connectivity"
    return "network"


def _navigation_error_origin(reason: object) -> str:
    if "ERR_CERT_VERIFIER_CHANGED" in str(reason or "").upper():
        return "local_runtime"
    return "remote_network"


def _navigation_error_retryable(reason: object) -> bool:
    value = str(reason or "").upper()
    return (
        "ERR_CERT_VERIFIER_CHANGED" in value
        or _network_failure_class(value) != "tls_certificate"
    )


def _main_document_network_reason(failure_class: object) -> str:
    return {
        "tls_certificate": "MAIN_DOCUMENT_TLS_ERROR",
        "dns": "MAIN_DOCUMENT_DNS_ERROR",
        "timeout": "MAIN_DOCUMENT_TIMEOUT",
        "connectivity": "MAIN_DOCUMENT_CONNECTION_ERROR",
    }.get(str(failure_class or ""), "MAIN_DOCUMENT_NETWORK_ERROR")


def _read_json(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    return payload if isinstance(payload, dict) else {}
