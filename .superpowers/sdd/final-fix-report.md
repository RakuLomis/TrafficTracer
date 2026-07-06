# Final Fix Report — TrafficTracer Dashboard

## Critical Fixes

### 1. Subprocess tracking + exit code checking — `dashboard/runner.py`
- Store `proc` handle on the queue (`ws_queue._proc = proc`) so it can be cancelled externally
- Check `proc.returncode` after `await proc.wait()`:
  - Non-zero: push `{"line": "[ERROR] ..."}` then `{"error": True, "code": N}`
  - Zero: push `None` (success signal, unchanged)

### 2. Resource leak with capture_queues — `dashboard/server.py`
- Added `finally` blocks in both WebSocket handlers (`ws_capture_log`, `ws_session_log`) that call `capture_queues.pop(session_id, None)` / `analysis_queues.pop(session_id, None)`
- Prevents unbounded growth of queue dicts on disconnect/timeout/completion

### 3. Config PUT validation — `dashboard/server.py` + `dashboard/config_manager.py`
- `api_put_config`: validates `"global"` and `"sites"` keys, returns 400 with error message if missing
- `save_config`: performs `yaml.dump` then `yaml.safe_load` round-trip to verify data is YAML-safe before writing

## Important Fixes

### 4. Removed unused `cfg` variable — `dashboard/server.py:api_capture_start`
- Removed the unnecessary `cfg = load_config()` line

### 5. Sort sessions by modification time — `dashboard/session_store.py:list_sessions`
- Changed `sorted(base.iterdir(), reverse=True)` to `sorted(base.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)`

### 6. Removed unused `stats` parameter — `dashboard/session_store.py:_session_status`
- Removed the unused `stats` param from `_session_status` signature and all call sites

### 7. Removed debugging `/test-base` endpoint — `dashboard/server.py`
- Removed the `@app.get("/test-base")` endpoint

### 8. Removed `python-multipart` from README
- Changed `pip install fastapi uvicorn python-multipart` to `pip install fastapi uvicorn`

## Test Results

```
test/test_dashboard.py::test_config_api PASSED
test/test_dashboard.py::test_session_api PASSED
test/test_dashboard.py::test_session_detail PASSED
test/test_dashboard.py::test_session_not_found PASSED
test/test_dashboard.py::test_pages_render PASSED
```

All 5 tests passed.
