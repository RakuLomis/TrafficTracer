"""Read and write TrafficTracer sites.yaml configuration."""

from pathlib import Path
import yaml

DEFAULT_CONFIG_PATH = str(Path(__file__).resolve().parent.parent / "sites.yaml")


def load_config(path: str = DEFAULT_CONFIG_PATH) -> dict:
    """Load sites.yaml and return normalized dict."""
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def save_config(data: dict, path: str = DEFAULT_CONFIG_PATH) -> None:
    """Write dict back to sites.yaml, preserving structure."""
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
