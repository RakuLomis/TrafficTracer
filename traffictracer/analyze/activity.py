"""Evidence-backed page navigation and application outcome classification."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from urllib.parse import urldefrag


_CRITICAL_RESOURCE_TYPES = frozenset({"script", "stylesheet", "font"})
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
    }
    if not cdp:
        return _outcome(base, "not_applicable", "CDP_EVIDENCE_UNAVAILABLE")
    error_text = str(navigation.get("error_text") or "")
    if error_text:
        base["error_text"] = error_text
        return _outcome(base, "failed", "NAVIGATION_COMMAND_ERROR")

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
        return _outcome(base, "indeterminate", "MAIN_DOCUMENT_NOT_OBSERVED")

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
    prior_http_error = any(status >= 400 for status in status_chain[:-1])
    if final_status in {408, 429}:
        return _outcome(base, "failed", "MAIN_DOCUMENT_TRANSIENT_HTTP_ERROR")
    if final_status is not None and final_status >= 500:
        return _outcome(base, "failed", "MAIN_DOCUMENT_SERVER_ERROR")
    if final_status is not None and final_status >= 400:
        return _outcome(base, "failed", "MAIN_DOCUMENT_HTTP_ERROR")
    if bool(final.get("failed")) and not final_status:
        return _outcome(base, "failed", "MAIN_DOCUMENT_NETWORK_ERROR")
    if final_status is None or final_status <= 0:
        return _outcome(base, "indeterminate", "MAIN_DOCUMENT_RESPONSE_UNKNOWN")
    if 300 <= final_status < 400:
        return _outcome(base, "indeterminate", "MAIN_DOCUMENT_REDIRECT_INCOMPLETE")
    if 200 <= final_status < 300:
        if prior_http_error:
            base["recovered"] = True
            return _outcome(
                base, "degraded", "MAIN_DOCUMENT_HTTP_ERROR_RECOVERED",
            )
        if nav_status in _RECOVERED_NAVIGATION_STATES:
            base["recovered"] = True
            return _outcome(
                base, "degraded", "NAVIGATION_TIMEOUT_RECOVERED",
            )
        if nav_status in _UNRESOLVED_NAVIGATION_STATES:
            return _outcome(base, "degraded", "NAVIGATION_COMPLETION_UNCERTAIN")
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
    latest_success: dict[str, int] = {}
    for index, item in enumerate(requests):
        url = _normalized_url(item.get("url"))
        if url and not _request_failed(item):
            latest_success[url] = index
    failures = []
    recovered = 0
    for index, item in enumerate(requests):
        if not _request_failed(item):
            continue
        url = _normalized_url(item.get("url"))
        if url and latest_success.get(url, -1) > index:
            recovered += 1
            continue
        failures.append(item)
    total = len(requests)
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
    systemic = failure_count >= 3 and ratio >= 0.20
    return {
        "state": "degraded" if systemic else "passed",
        "reason": "CRITICAL_RESOURCE_FAILURE_BURST" if systemic else None,
        "critical_requests": total,
        "unrecovered_failures": failure_count,
        "recovered_failures": recovered,
        "failure_ratio": round(ratio, 6),
        "failure_reasons": dict(sorted(reasons.items())),
        "failure_types": dict(sorted(types.items())),
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
    })
    return result


def _outcome(base: dict, state: str, reason: str | None) -> dict:
    return {**base, "state": state, "reason": reason}


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


def _read_json(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    return payload if isinstance(payload, dict) else {}
