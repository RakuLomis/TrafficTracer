"""Tests for validated Worker method routing and stable responses."""

import pytest

from traffictracer.contracts import validate_worker_message
from traffictracer.worker.dispatcher import Dispatcher, METHODS, WorkerMethodError
from traffictracer.worker.protocol import ProtocolFailure


def _request(method="hello", request_id="one", params=None, api_version=1):
    return {
        "api_version": api_version,
        "type": "request",
        "id": request_id,
        "method": method,
        "params": params or {},
    }


def test_hello_returns_all_protocol_versions_and_methods():
    response = Dispatcher().dispatch(_request())
    assert validate_worker_message(response) is response
    result = response["result"]
    assert result["api_version"] == 1
    assert result["job_schema_version"] == 1
    assert result["session_schema_version"] == 1
    assert result["flow_schema_version"] == 1
    assert result["methods"] == list(METHODS)


def test_every_diagnose_job_session_and_flow_method_routes_params():
    routed = []
    methods = [method for method in METHODS if method != "hello"]
    handlers = {
        method: (
            lambda params, current=method: routed.append((current, params))
            or {"method": current}
        )
        for method in methods
    }
    dispatcher = Dispatcher(handlers)
    for index, method in enumerate(methods):
        response = dispatcher.dispatch(
            _request(method, request_id=index, params={"value": index})
        )
        assert validate_worker_message(response) is response
        assert response["result"] == {"method": method}
    assert [method for method, _ in routed] == methods


def test_unknown_method_returns_method_not_found_without_crashing():
    response = Dispatcher().dispatch(_request("unknown.method"))
    assert response["error"]["code"] == "METHOD_NOT_FOUND"
    assert validate_worker_message(response) is response


def test_invalid_params_and_non_request_envelopes_are_stable_errors():
    invalid_params = _request(params={})
    invalid_params["params"] = []
    response = Dispatcher().dispatch(invalid_params)
    assert response["error"]["code"] == "INVALID_PARAMS"
    assert response["error"]["data"]["path"] == ["params"]

    non_request = {
        "api_version": 1,
        "type": "response",
        "id": "response-id",
        "result": {},
    }
    response = Dispatcher().dispatch(non_request)
    assert response["error"]["code"] == "INVALID_REQUEST"
    assert validate_worker_message(response) is response


def test_duplicate_request_id_is_rejected_even_after_method_error():
    dispatcher = Dispatcher({
        "job.status": lambda params: (_ for _ in ()).throw(
            WorkerMethodError("JOB_NOT_FOUND", "No such Job.")
        )
    })
    first = dispatcher.dispatch(_request("job.status", request_id=7))
    second = dispatcher.dispatch(_request("job.status", request_id=7))
    assert first["error"]["code"] == "JOB_NOT_FOUND"
    assert second["error"]["code"] == "INVALID_REQUEST"
    assert second["error"]["data"]["reason"] == "DUPLICATE_REQUEST_ID"


def test_protocol_version_mismatch_and_framing_error_are_valid_responses():
    mismatch = Dispatcher().dispatch(_request(api_version=2))
    assert mismatch["error"]["code"] == "PROTOCOL_VERSION_MISMATCH"
    assert validate_worker_message(mismatch) is mismatch

    framing = Dispatcher().dispatch(ProtocolFailure("INVALID_JSON", "Bad JSON."))
    assert framing["id"] is None
    assert framing["error"]["code"] == "INVALID_REQUEST"
    assert validate_worker_message(framing) is framing


def test_handler_errors_map_to_allowed_codes_and_hide_internal_details():
    dispatcher = Dispatcher({
        "job.cancel": lambda params: (_ for _ in ()).throw(
            WorkerMethodError("JOB_NOT_FOUND", "No such Job.", {"job_id": "missing"})
        ),
        "flow.query": lambda params: (_ for _ in ()).throw(
            RuntimeError("secret implementation detail")
        ),
    })
    expected = dispatcher.dispatch(_request("job.cancel", request_id="cancel"))
    assert expected["error"] == {
        "code": "JOB_NOT_FOUND",
        "message": "No such Job.",
        "data": {"job_id": "missing"},
    }
    internal = dispatcher.dispatch(_request("flow.query", request_id="query"))
    assert internal["error"]["code"] == "INTERNAL_ERROR"
    assert "secret implementation detail" not in internal["error"]["message"]
    assert validate_worker_message(internal) is internal


def test_dispatcher_rejects_unknown_handler_registration():
    with pytest.raises(ValueError, match="unknown Worker handlers"):
        Dispatcher({"not.real": lambda params: None})
