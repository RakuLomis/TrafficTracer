"""Contract checks for the maintained TrafficTracer documentation."""

from pathlib import Path
import re
import subprocess

import yaml


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
GUIDE = ROOT / "docs" / "complete" / "quickstart.md"
LOCK = ROOT / "complete" / "components.lock.yaml"
ACTIVE_DOCS = (
    README,
    ROOT / "CHANGELOG.md",
    ROOT / "THIRD_PARTY_NOTICES.md",
    ROOT / "docs" / "README.md",
    ROOT / "docs" / "architecture.md",
    GUIDE,
    ROOT / "docs" / "configuration.md",
    ROOT / "docs" / "data-model.md",
    ROOT / "docs" / "development.md",
    ROOT / "docs" / "operations.md",
    ROOT / "docs" / "release-checklist.md",
    ROOT / "docs" / "releases" / "v1.0.4.md",
    ROOT / "docs" / "releases" / "v1.0.1.md",
    ROOT / "docs" / "releases" / "v1.0.0.md",
    ROOT / "docs" / "standalone-tools.md",
    ROOT / "test" / "e2e" / "tun" / "README.md",
)
LOCAL_LINK = re.compile(r"\[[^]]+\]\((?!https?://|mailto:|#)([^)#]+)(?:#[^)]+)?\)")
CJK = re.compile(r"[\u3400-\u9fff]")


def test_complete_readme_is_a_small_pinned_entrypoint() -> None:
    section = README.read_text(encoding="utf-8")
    headings = [line for line in section.splitlines() if line.startswith("## ")]
    assert headings == [
        "## Supported release",
        "## QuickStart",
        "## Build from source",
        "## Documentation",
        "## License",
    ]
    assert len(section.splitlines()) <= 160
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


def test_active_documentation_is_english_and_has_valid_local_links() -> None:
    for path in ACTIVE_DOCS:
        assert path.is_file(), path
        text = path.read_text(encoding="utf-8")
        assert not CJK.search(text), path
        for target in LOCAL_LINK.findall(text):
            resolved = (path.parent / target).resolve()
            assert resolved.exists(), f"broken link in {path}: {target}"


def test_detailed_topics_live_under_docs() -> None:
    readme = README.read_text(encoding="utf-8")
    assert "## Architecture" not in readme
    assert "## Data Pipeline" not in readme
    assert "## Configuration Reference" not in readme
    assert "## Troubleshooting" not in readme
    for name in (
        "architecture.md",
        "configuration.md",
        "data-model.md",
        "operations.md",
        "development.md",
        "standalone-tools.md",
    ):
        assert (ROOT / "docs" / name).is_file()


def test_obsolete_internal_plans_are_not_tracked() -> None:
    completed = subprocess.run(
        ["git", "ls-files", "docs/superpowers", ".superpowers"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    assert completed.stdout.strip() == ""
