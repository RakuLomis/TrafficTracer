"""NetLog JSON validation and truncated repair."""

from __future__ import annotations

import json
from pathlib import Path
import shutil

from ..utils import logger


def validate_json(path: str) -> bool:
    try:
        with open(path, "r", encoding="utf-8") as f:
            json.load(f)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


def repair_truncated_netlog(path: str) -> bool:
    if validate_json(path):
        return True

    with open(path, "r", encoding="utf-8") as f:
        original = f.read()

    bak_path = path + ".truncated.bak"
    shutil.copy2(path, bak_path)
    logger.info("Backed up truncated NetLog to %s", bak_path)

    stripped = original.rstrip()
    if stripped.endswith(","):
        stripped = stripped[:-1]

    for suffix in ("\n]}\n", "\n}\n"):
        repaired = stripped + suffix
        with open(path, "w", encoding="utf-8") as f:
            f.write(repaired)
        if validate_json(path):
            logger.info("NetLog repaired successfully: %s", path)
            return True

    with open(path, "w", encoding="utf-8") as f:
        f.write(original)
    logger.warning("NetLog repair failed, original restored: %s", path)
    return False
