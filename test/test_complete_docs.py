"""Contract checks for the TrafficTracer Complete entry documentation."""

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
GUIDE = ROOT / "docs" / "complete" / "quickstart.md"
LOCK = ROOT / "complete" / "components.lock.yaml"


def test_complete_readme_uses_the_pinned_single_repo_entrypoint() -> None:
    section = README.read_text(encoding="utf-8").split("## Architecture", 1)[0]
    assert "--branch Complete --recurse-submodules" in section
    assert "docs/complete/quickstart.md" in section
    assert "make dev" in section
    assert "make package-linux" in section
    for legacy in (
        "TT_WORKSPACE",
        "cd ../mihomo",
        "python capture.py",
        "python analyze.py",
        "python query_flow.py",
    ):
        assert legacy not in section


def test_complete_guide_documents_current_protocol_versions() -> None:
    guide = GUIDE.read_text(encoding="utf-8")
    lock = yaml.safe_load(LOCK.read_text(encoding="utf-8"))
    assert lock["product"]["version"] in guide
    for version in lock["protocols"].values():
        assert f"| {version} |" in guide
    assert "post_flow=null" in guide
    assert "post_flow.shared=true" in guide


def test_complete_guide_has_no_manual_capture_or_sibling_dependency() -> None:
    guide = GUIDE.read_text(encoding="utf-8")
    for forbidden in (
        "python capture.py",
        "python analyze.py",
        "python query_flow.py",
        "MIHOMO_TRAFFIC_TRACER_BIN=",
        "TT_WORKSPACE",
    ):
        assert forbidden not in guide
    assert (ROOT / "docs" / "complete" / "quickstart.md").is_file()
