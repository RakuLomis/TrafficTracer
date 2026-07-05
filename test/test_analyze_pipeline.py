"""Tests for analysis pipeline result serialization."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
from traffictracer.analyze.netlog import FiveTupleData
from traffictracer.analyze.correlator import CorrelationResult, CorrelatedFlow
from traffictracer.analyze.pipeline import _result_to_dict


def test_result_to_dict():
    result = CorrelationResult(
        domain="example.com",
        flows=[
            CorrelatedFlow(
                name="https://www.example.com",
                relation="same_site",
                pre_proxy=FiveTupleData("127.0.0.1", 55555, "127.0.0.1", 7890, "tcp"),
                post_proxy=FiveTupleData("192.168.1.100", 41234, "1.2.3.4", 443, "tcp"),
            ),
        ],
    )
    d = _result_to_dict(result)
    assert len(d) == 1
    assert d[0]["name"] == "https://www.example.com"
    assert d[0]["pre_proxy"]["src"] == "127.0.0.1:55555"
    assert d[0]["post_proxy"]["dst"] == "1.2.3.4:443"
    assert d[0]["relation"] == "same_site"


def test_json_roundtrip():
    result = CorrelationResult(
        domain="test.com",
        flows=[
            CorrelatedFlow(
                name="https://cdn.test.com",
                relation="cross_site",
                pre_proxy=FiveTupleData("10.0.0.1", 443, "10.0.0.2", 8080, "tcp"),
                post_proxy=FiveTupleData("", 0, "", 0, ""),
            ),
        ],
    )
    d = _result_to_dict(result)
    j = json.dumps(d)
    parsed = json.loads(j)
    assert parsed[0]["name"] == "https://cdn.test.com"
    assert parsed[0]["post_proxy"]["src"] == ""


if __name__ == "__main__":
    test_result_to_dict()
    test_json_roundtrip()
    print("\n✓ All analysis pipeline tests passed!")
