"""Build a clean environment for processes launched outside TrafficTracer.

Frozen application bundles prepend their private library directory to
``LD_LIBRARY_PATH`` (and occasionally ``LD_PRELOAD``).  Passing that environment
to Chrome, tshark, or Mihomo can make those system programs load ABI-incompatible
copies of common libraries.  External tools must instead inherit the original
launcher environment.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Mapping


def _inside_bundle(entry: str, bundle_root: str | None) -> bool:
    if not entry or not bundle_root:
        return False
    try:
        return Path(entry).resolve().is_relative_to(Path(bundle_root).resolve())
    except (OSError, RuntimeError, ValueError):
        return entry == bundle_root or entry.startswith(bundle_root.rstrip("/") + "/")


def _without_bundle_entries(value: str | None, bundle_root: str | None) -> str | None:
    if value is None:
        return None
    entries = [entry for entry in value.split(os.pathsep) if not _inside_bundle(entry, bundle_root)]
    return os.pathsep.join(entries) or None


def external_process_env(
    source: Mapping[str, str] | None = None,
    *,
    frozen: bool | None = None,
    bundle_root: str | None = None,
) -> dict[str, str]:
    """Return an environment safe for system executables.

    PyInstaller preserves the pre-bundle library path in
    ``LD_LIBRARY_PATH_ORIG``.  Restore it when available, then defensively remove
    any remaining entries inside ``sys._MEIPASS`` from both loader variables.
    Non-frozen development runs retain the environment unchanged.
    """

    env = dict(os.environ if source is None else source)
    is_frozen = bool(getattr(sys, "frozen", False)) if frozen is None else frozen
    if not is_frozen:
        return env

    root = bundle_root if bundle_root is not None else getattr(sys, "_MEIPASS", None)
    original = env.pop("LD_LIBRARY_PATH_ORIG", None)
    if original is not None:
        if original:
            env["LD_LIBRARY_PATH"] = original
        else:
            env.pop("LD_LIBRARY_PATH", None)

    for variable in ("LD_LIBRARY_PATH", "LD_PRELOAD"):
        cleaned = _without_bundle_entries(env.get(variable), root)
        if cleaned:
            env[variable] = cleaned
        else:
            env.pop(variable, None)
    return env
