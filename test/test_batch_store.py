"""Persistence recovery tests for the TT-046 batch store."""

import json
from pathlib import Path

from traffictracer.jobs.batch_models import BatchJobSpec, BatchManifest, BatchState, BatchStore


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "test" / "fixtures" / "contracts" / "job-valid-batch.json"


def test_batch_store_reports_corrupt_without_hiding_valid(tmp_path):
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["output_root"] = str(tmp_path)
    manifest = BatchManifest.create(BatchJobSpec.from_dict(payload))
    store = BatchStore(tmp_path)
    store.save(manifest)
    broken = store.root / "broken"
    broken.mkdir()
    (broken / "batch-manifest.json").write_text("{bad", encoding="utf-8")

    scan = store.scan()
    assert [item.batch_id for item in scan.batches] == [manifest.batch_id]
    assert len(scan.corrupt) == 1


def test_idle_running_batch_is_interrupted_once(tmp_path):
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["output_root"] = str(tmp_path)
    running = BatchManifest.create(BatchJobSpec.from_dict(payload)).begin()
    store = BatchStore(tmp_path)
    store.save(running)
    assert store.recover_running() == (running.batch_id,)
    assert store.get(running.batch_id).state is BatchState.INTERRUPTED
    assert store.recover_running() == ()
