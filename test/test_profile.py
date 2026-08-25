"""Safety tests for TrafficTracer-owned Chrome scratch profiles."""

from pathlib import Path

import pytest

from traffictracer.capture.profile import (
    MARKER_NAME,
    ProfileCleanupError,
    ProfileOwnershipError,
    remove_owned_cold_profile,
    remove_recovered_cold_profile,
    resolve_owned_profile_root,
)


SESSION_ID = "5027aee9-c6e4-41de-8625-7ea0869a3307"


def test_owned_root_marker_and_exact_cold_profile_cleanup(tmp_path):
    root = resolve_owned_profile_root(tmp_path / "traffictracer" / "profiles")
    profile = root / "cold" / "example.com" / SESSION_ID
    profile.mkdir(parents=True)
    (profile / "state").write_text("owned", encoding="utf-8")
    unrelated = root / "warm" / "example.com" / "main-page"
    unrelated.mkdir(parents=True)

    remove_owned_cold_profile(profile, root, SESSION_ID)

    assert (root / MARKER_NAME).is_file()
    assert not profile.exists()
    assert unrelated.is_dir()


def test_profile_root_rejects_relative_broad_symlink_and_browser_paths(tmp_path):
    with pytest.raises(ProfileOwnershipError, match="absolute"):
        resolve_owned_profile_root("relative-profile")
    with pytest.raises(ProfileOwnershipError, match="too broad"):
        resolve_owned_profile_root(Path("/"))
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(ProfileOwnershipError, match="symlink"):
        resolve_owned_profile_root(link)
    with pytest.raises(ProfileOwnershipError, match="user browser"):
        resolve_owned_profile_root(tmp_path / "google-chrome" / "profiles")


def test_cleanup_rejects_outside_wrong_session_and_symlink(tmp_path):
    root = resolve_owned_profile_root(tmp_path / "traffictracer" / "profiles")
    outside = tmp_path / "outside" / SESSION_ID
    outside.mkdir(parents=True)
    with pytest.raises(ProfileOwnershipError, match="outside"):
        remove_owned_cold_profile(outside, root, SESSION_ID)
    wrong = root / "cold" / "example.com" / SESSION_ID
    wrong.mkdir(parents=True)
    with pytest.raises(ProfileOwnershipError, match="does not match"):
        remove_owned_cold_profile(
            wrong, root, "76904d43-1852-43a8-a37b-c2b719250bcd"
        )
    link = root / "cold" / "linked.example" / SESSION_ID
    link.parent.mkdir(parents=True)
    link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ProfileOwnershipError, match="non-symlinked"):
        remove_owned_cold_profile(link, root, SESSION_ID)
    assert outside.is_dir()


def test_bounded_cleanup_failure_is_visible_and_preserves_profile(tmp_path, monkeypatch):
    import traffictracer.capture.profile as module

    root = resolve_owned_profile_root(tmp_path / "traffictracer" / "profiles")
    profile = root / "cold" / "example.com" / SESSION_ID
    profile.mkdir(parents=True)
    monkeypatch.setattr(
        module.shutil,
        "rmtree",
        lambda path: (_ for _ in ()).throw(OSError("busy")),
    )

    with pytest.raises(ProfileCleanupError, match="busy"):
        remove_owned_cold_profile(profile, root, SESSION_ID, attempts=2)
    assert profile.is_dir()


def test_recovery_ignores_unmarked_legacy_profile(tmp_path):
    profile = tmp_path / "legacy" / SESSION_ID
    profile.mkdir(parents=True)

    assert remove_recovered_cold_profile(profile, SESSION_ID) is False
    assert profile.is_dir()


def test_recovery_preserves_marked_warm_profile(tmp_path):
    root = resolve_owned_profile_root(tmp_path / "traffictracer" / "profiles")
    profile = root / "warm" / "example.com" / "main-page"
    profile.mkdir(parents=True)
    (profile / "state").write_text("reusable", encoding="utf-8")

    assert remove_recovered_cold_profile(profile, SESSION_ID) is False
    assert (profile / "state").read_text(encoding="utf-8") == "reusable"


def test_recovery_rejects_unexpected_marked_profile_layout(tmp_path):
    root = resolve_owned_profile_root(tmp_path / "traffictracer" / "profiles")
    profile = root / "other" / "example.com" / SESSION_ID
    profile.mkdir(parents=True)

    with pytest.raises(ProfileOwnershipError, match="unexpected owned layout"):
        remove_recovered_cold_profile(profile, SESSION_ID)
    assert profile.is_dir()
