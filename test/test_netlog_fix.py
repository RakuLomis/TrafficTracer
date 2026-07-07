"""Tests for NetLog JSON repair."""
import json
import os
import sys
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.capture.netlog_fix import validate_json, repair_truncated_netlog


def _write_temp(content):
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    tmp.write(content)
    tmp.close()
    return tmp.name


def test_validate_json_valid():
    path = _write_temp('{"a": 1}')
    try:
        assert validate_json(path) is True
    finally:
        os.unlink(path)


def test_validate_json_invalid():
    path = _write_temp('{"a": 1,')
    try:
        assert validate_json(path) is False
    finally:
        os.unlink(path)


def test_repair_already_valid():
    path = _write_temp('{"a": 1}\n')
    try:
        assert repair_truncated_netlog(path) is True
        with open(path) as f:
            assert json.load(f) == {"a": 1}
    finally:
        os.unlink(path)


def test_repair_truncated_with_comma():
    path = _write_temp('{"a": 1,\n"b": 2,')
    try:
        assert repair_truncated_netlog(path) is True
        with open(path) as f:
            assert json.load(f) == {"a": 1, "b": 2}
        # Backup should exist
        bak = path + ".truncated.bak"
        assert os.path.exists(bak)
        os.unlink(bak)
    finally:
        os.unlink(path)


def test_repair_truncated_netlog_style():
    path = _write_temp('{"constants": {"a": 1},\n"events": [\n{"e":1},\n{"e":2},\n')
    try:
        result = repair_truncated_netlog(path)
        with open(path) as f:
            data = json.load(f)
        assert len(data["events"]) == 2
        bak = path + ".truncated.bak"
        assert os.path.exists(bak)
        os.unlink(bak)
    finally:
        os.unlink(path)


def test_repair_unfixable():
    content = 'not json at all {{{'
    path = _write_temp(content)
    try:
        assert repair_truncated_netlog(path) is False
        with open(path) as f:
            assert f.read() == content
        bak = path + ".truncated.bak"
        assert os.path.exists(bak)
        os.unlink(bak)
    finally:
        os.unlink(path)


def test_repair_value_list_truncated():
    path = _write_temp('["events", [')
    try:
        result = repair_truncated_netlog(path)
        bak = path + ".truncated.bak"
        assert os.path.exists(bak)
        os.unlink(bak)
    finally:
        os.unlink(path)


if __name__ == "__main__":
    test_validate_json_valid()
    test_validate_json_invalid()
    test_repair_already_valid()
    test_repair_truncated_with_comma()
    test_repair_truncated_netlog_style()
    test_repair_unfixable()
    test_repair_value_list_truncated()
    print("\n✓ All NetLog fix tests passed!")
