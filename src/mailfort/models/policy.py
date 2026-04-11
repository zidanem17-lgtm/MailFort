"""Policy result model."""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


@dataclass
class PolicyResult:
    """The outcome of applying the policy engine to a verdict."""

    action: str          # allow | warn | quarantine | block | escalate
    message_id: str
    severity: str
    reasons: List[str] = field(default_factory=list)
    label_applied: Optional[str] = None
    quarantined: bool = False
    notified: bool = False
    dry_run: bool = False
    applied_ts: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "message_id": self.message_id,
            "severity": self.severity,
            "reasons": self.reasons,
            "label_applied": self.label_applied,
            "quarantined": self.quarantined,
            "notified": self.notified,
            "dry_run": self.dry_run,
            "applied_ts": self.applied_ts,
        }
