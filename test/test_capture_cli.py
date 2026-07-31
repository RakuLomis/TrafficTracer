"""Smoke tests for the legacy capture CLI boundary."""

import capture as capture_cli


def test_capture_cli_routes_loaded_yaml_to_job_pipeline(monkeypatch, capsys):
    config = object()
    calls = []
    monkeypatch.setattr(capture_cli, "load_config", lambda path: config)
    monkeypatch.setattr(
        capture_cli,
        "run_capture",
        lambda loaded, only_domain=None: calls.append((loaded, only_domain))
        or "/tmp/session",
    )
    result = capture_cli.main(["--config", "sites.yaml", "--only", "example.com"])
    assert result == 0
    assert calls == [(config, "example.com")]
    assert "Capture session saved to: /tmp/session" in capsys.readouterr().out


def test_capture_cli_reports_sigint_after_pipeline_cleanup(monkeypatch, capsys):
    monkeypatch.setattr(capture_cli, "load_config", lambda path: object())

    def interrupt(config, only_domain=None):
        raise KeyboardInterrupt

    monkeypatch.setattr(capture_cli, "run_capture", interrupt)
    assert capture_cli.main(["--config", "sites.yaml"]) == 130
    assert "cleanup completed" in capsys.readouterr().err


def test_capture_cli_config_error_is_nonzero(monkeypatch, capsys):
    def fail(path):
        raise ValueError("invalid YAML")

    monkeypatch.setattr(capture_cli, "load_config", fail)
    assert capture_cli.main(["--config", "bad.yaml"]) == 1
    assert "invalid YAML" in capsys.readouterr().err
