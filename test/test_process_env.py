from traffictracer.process_env import external_process_env


def test_non_frozen_environment_is_copied_without_changes():
    source = {"PATH": "/usr/bin", "LD_LIBRARY_PATH": "/custom/lib"}

    result = external_process_env(source, frozen=False, bundle_root="/tmp/_MEI123")

    assert result == source
    assert result is not source


def test_frozen_environment_restores_original_library_path():
    source = {
        "PATH": "/usr/bin",
        "LD_LIBRARY_PATH": "/tmp/_MEI123:/custom/lib",
        "LD_LIBRARY_PATH_ORIG": "/usr/local/lib:/usr/lib",
    }

    result = external_process_env(source, frozen=True, bundle_root="/tmp/_MEI123")

    assert result["LD_LIBRARY_PATH"] == "/usr/local/lib:/usr/lib"
    assert "LD_LIBRARY_PATH_ORIG" not in result


def test_frozen_environment_removes_only_bundle_loader_entries():
    source = {
        "LD_LIBRARY_PATH": "/tmp/_MEI123:/opt/vendor/lib",
        "LD_PRELOAD": "/tmp/_MEI123/libz.so.1:/opt/vendor/libhook.so",
        "DISPLAY": ":0",
    }

    result = external_process_env(source, frozen=True, bundle_root="/tmp/_MEI123")

    assert result["LD_LIBRARY_PATH"] == "/opt/vendor/lib"
    assert result["LD_PRELOAD"] == "/opt/vendor/libhook.so"
    assert result["DISPLAY"] == ":0"


def test_empty_original_library_path_removes_bundle_value():
    source = {
        "LD_LIBRARY_PATH": "/tmp/_MEI123",
        "LD_LIBRARY_PATH_ORIG": "",
    }

    result = external_process_env(source, frozen=True, bundle_root="/tmp/_MEI123")

    assert "LD_LIBRARY_PATH" not in result
    assert "LD_LIBRARY_PATH_ORIG" not in result
