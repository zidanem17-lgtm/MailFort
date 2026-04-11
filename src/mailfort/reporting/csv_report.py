"""CSV report writer."""

import csv
import os
from typing import Any, Dict, List


def write_csv_report(cases: List[Dict[str, Any]], path: str) -> None:
    """Write a flat CSV with one row per message case."""
    os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None

    fieldnames = [
        "message_id", "sender", "sender_domain", "subject", "provider",
        "static_score", "dynamic_score", "final_score",
        "severity", "confidence", "action",
        "url_count", "attachment_count",
        "reasons",
    ]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for case in cases:
            m = case.get("message", {})
            v = case.get("verdict", {})
            p = case.get("policy", {})
            static = case.get("static_analysis", {})
            writer.writerow({
                "message_id": m.get("message_id"),
                "sender": m.get("sender"),
                "sender_domain": m.get("sender_domain"),
                "subject": m.get("subject"),
                "provider": m.get("provider"),
                "static_score": v.get("static_score"),
                "dynamic_score": v.get("dynamic_score"),
                "final_score": v.get("final_score"),
                "severity": v.get("severity"),
                "confidence": v.get("confidence"),
                "action": p.get("action"),
                "url_count": len(static.get("urls", [])),
                "attachment_count": m.get("attachment_count", 0),
                "reasons": "; ".join(v.get("reasons", [])[:5]),
            })
