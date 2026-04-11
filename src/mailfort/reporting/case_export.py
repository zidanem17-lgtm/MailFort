"""Case export — write individual case bundles to disk."""

import json
import os
from typing import Any, Dict

from ..constants import DEFAULT_REPORT_DIR


def export_case(case: Dict[str, Any], report_dir: str = DEFAULT_REPORT_DIR) -> str:
    """Write a single case bundle to a JSON file and return the path."""
    os.makedirs(report_dir, exist_ok=True)
    message_id = case.get("message", {}).get("message_id", "unknown")
    safe_id = message_id.replace("/", "_").replace("\\", "_")[:64]
    path = os.path.join(report_dir, f"case_{safe_id}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(case, f, indent=2, default=str)
    return path


def export_all_cases(cases: list, report_dir: str = DEFAULT_REPORT_DIR) -> list:
    """Export each case to its own file and return the list of paths."""
    return [export_case(c, report_dir) for c in cases]
