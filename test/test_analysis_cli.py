"""Integration tests for the AnalysisJob-backed compatibility CLI."""

import json

import analyze as analyze_cli


def test_analyze_cli_json_runs_legacy_session_through_job(tmp_path, capsys):
    session = tmp_path / "legacy-session"
    (session / "captures").mkdir(parents=True)
    (session / "logs").mkdir()
    result = analyze_cli.main(["--session", str(session), "--json"])
    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] == "completed"
    assert payload["session_id"]
    assert payload["artifacts"] == [
        "results/correlation.json",
        "results/flow-index.json",
        "results/summary.json",
    ]
    assert (session / "results" / "correlation.json").is_file()
    assert (session / "results" / "flow-index.json").is_file()
    assert (session / "results" / "summary.json").is_file()


def test_analyze_cli_missing_session_is_nonzero(tmp_path, capsys):
    result = analyze_cli.main(["--session", str(tmp_path / "missing")])
    assert result == 1
    assert "Session directory not found" in capsys.readouterr().err
