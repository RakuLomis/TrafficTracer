"""CLI routing tests for persisted batch management."""

import json

import batch as batch_cli


class FakeJobs:
    def wait(self, job_id, timeout=None):
        return True


class FakeServices:
    def __init__(self):
        self.jobs = FakeJobs()
        self.calls = []

    def batch_list(self, params):
        self.calls.append(("list", params))
        return {"batches": [], "corrupt": []}

    def batch_status(self, params):
        self.calls.append(("status", params))
        return {"batch": {"batch_id": params["batch_id"]}, "job": None}

    def batch_start(self, params):
        self.calls.append(("start", params))
        return {"job_id": params["job"]["job_id"]}

    def batch_resume(self, params):
        self.calls.append(("resume", params))
        return {"job_id": params["batch_id"]}

    def batch_cancel(self, params):
        self.calls.append(("cancel", params))
        return {"batch": {"batch_id": params["batch_id"]}, "job": None}

    def recover_batches(self):
        self.calls.append(("recover", {}))
        return ()


def test_batch_cli_start_waits_and_prints_persisted_status(tmp_path, monkeypatch, capsys):
    fake = FakeServices()
    monkeypatch.setattr(batch_cli, "_services", lambda args: fake)
    job = tmp_path / "batch.json"
    job.write_text(json.dumps({"job_id": "batch-one"}), encoding="utf-8")

    assert batch_cli.main([
        "--output-root", str(tmp_path), "start", str(job)
    ]) == 0
    assert [name for name, _ in fake.calls] == ["start", "status"]
    assert "batch-one" in capsys.readouterr().out


def test_batch_cli_resume_recovers_before_starting(tmp_path, monkeypatch):
    fake = FakeServices()
    monkeypatch.setattr(batch_cli, "_services", lambda args: fake)
    assert batch_cli.main([
        "--output-root", str(tmp_path), "resume", "batch-two"
    ]) == 0
    assert [name for name, _ in fake.calls] == ["recover", "resume", "status"]
