from datetime import datetime, timezone

import pytest

from traffictracer.layout import (
    CapturePageLayout,
    group_directory_name,
    normalize_page_types,
    page_directory_name,
    safe_url_slug,
)


def test_legacy_page_types_are_stable_and_unique():
    assert normalize_page_types([
        (None, "video-mainpage"),
        (None, "video-play"),
        (None, "video-play"),
    ]) == ["main-page", "video-play1", "video-play2"]


def test_explicit_page_types_are_authoritative_and_duplicates_fail():
    assert normalize_page_types([
        ("main-page", "all"),
        ("video-play1", "all"),
    ]) == ["main-page", "video-play1"]
    with pytest.raises(ValueError, match="duplicate page_type"):
        normalize_page_types([("main-page", "all"), ("main-page", "all")])


def test_url_slug_is_readable_bounded_and_query_safe():
    assert safe_url_slug("https://www.bilibili.com/video/BV1hu4m1P7Mu/") == (
        "https_www.bilibili.com_video_BV1hu4m1P7Mu"
    )
    slug = safe_url_slug("https://cdn.example/video.m4s?token=secret")
    assert slug.startswith("https_cdn.example_video.m4s__")
    assert "secret" not in slug
    assert len(slug) <= 120


def test_capture_page_layout_matches_the_user_visible_contract(tmp_path):
    started = datetime(2026, 8, 5, 15, 40, 36, 270000, timezone.utc)
    group = tmp_path / group_directory_name(started)
    layout = CapturePageLayout(
        group,
        "bilibili.com",
        "video-play1",
        "https://www.bilibili.com/video/BV1hu4m1P7Mu/",
    )
    assert layout.page_root.relative_to(tmp_path).parts == (
        "20260805-154036-270",
        "bilibili.com",
        "video-play1__https_www.bilibili.com_video_BV1hu4m1P7Mu",
    )
    layout.create()
    assert layout.raw_dir.is_dir()
    assert layout.analysis_dir.is_dir()


def test_page_directory_rejects_path_traversal():
    with pytest.raises(ValueError, match="unsafe page_type"):
        page_directory_name("../escape", "https://example.com")
