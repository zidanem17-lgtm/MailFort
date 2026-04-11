"""Quarantine management — query, release, and audit quarantined messages."""

import time
from typing import Any, Dict, List, Optional

from ..persistence.repositories import list_messages, log_audit, save_message


def list_quarantined(limit: int = 100) -> List[Dict[str, Any]]:
    """Return messages currently in quarantine disposition."""
    return [
        m for m in list_messages(limit=limit)
        if m.get("disposition") == "quarantine"
    ]


def mark_released(message_id: str, released_by: str = "admin") -> None:
    """Update the database to reflect a manual release."""
    log_audit(
        action="released",
        message_id=message_id,
        sender="",
        confirmed=True,
        details={"released_by": released_by, "ts": time.time()},
    )
    # Update disposition in the messages table
    from ..persistence.db import get_conn
    conn = get_conn()
    conn.execute(
        "UPDATE messages SET disposition = 'released' WHERE message_id = ?",
        (message_id,),
    )
    conn.commit()


def get_quarantine_summary() -> Dict[str, Any]:
    """Return aggregate stats for the quarantine queue."""
    messages = list_quarantined(limit=1000)
    by_severity: Dict[str, int] = {}
    for m in messages:
        sev = m.get("severity", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
    return {
        "total": len(messages),
        "by_severity": by_severity,
        "messages": messages,
    }
