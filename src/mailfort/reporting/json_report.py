"""JSON report writer."""

import json
import os
from typing import Any, Dict, List


def write_json_report(cases: List[Dict[str, Any]], path: str) -> None:
    """Write a list of case bundles to a JSON file."""
    os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cases, f, indent=2, default=str)


def write_summary_json(summary: Dict[str, Any], path: str) -> None:
    """Write a scan summary to a JSON file."""
    os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, default=str)
