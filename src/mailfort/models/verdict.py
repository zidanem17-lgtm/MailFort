"""Verdict and sandbox evidence models."""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


@dataclass
class SandboxEvidence:
    """Behavioral evidence collected from sandbox detonation of a URL or attachment."""

    artifact_type: str    # url | attachment
    artifact_ref: str     # URL string or attachment SHA-256
    status: str           # completed | timeout | error | skipped

    screenshots: List[str] = field(default_factory=list)  # file paths
    final_url: Optional[str] = None
    final_domain: Optional[str] = None
    redirect_count: int = 0

    network_callbacks: List[Dict[str, Any]] = field(default_factory=list)
    process_tree: List[Dict[str, Any]] = field(default_factory=list)
    file_drops: List[Dict[str, Any]] = field(default_factory=list)
    registry_changes: List[Dict[str, Any]] = field(default_factory=list)
    persistence_signals: List[Dict[str, Any]] = field(default_factory=list)
    credential_harvest_signals: List[Dict[str, Any]] = field(default_factory=list)

    reasons: List[str] = field(default_factory=list)

    # Hard-fail flags — any true value drives score to critical
    detected_credential_harvest: bool = False
    detected_executable_network_callback: bool = False
    detected_persistence: bool = False
    detected_login_form: bool = False
    detected_file_download: bool = False

    dynamic_score: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_type": self.artifact_type,
            "artifact_ref": self.artifact_ref,
            "status": self.status,
            "screenshots": self.screenshots,
            "final_url": self.final_url,
            "final_domain": self.final_domain,
            "redirect_count": self.redirect_count,
            "network_callbacks": self.network_callbacks,
            "process_tree": self.process_tree,
            "file_drops": self.file_drops,
            "registry_changes": self.registry_changes,
            "persistence_signals": self.persistence_signals,
            "credential_harvest_signals": self.credential_harvest_signals,
            "reasons": self.reasons,
            "detected_credential_harvest": self.detected_credential_harvest,
            "detected_executable_network_callback": self.detected_executable_network_callback,
            "detected_persistence": self.detected_persistence,
            "detected_login_form": self.detected_login_form,
            "detected_file_download": self.detected_file_download,
            "dynamic_score": self.dynamic_score,
        }


@dataclass
class Verdict:
    """Final verdict for a scanned message."""

    message_id: str
    static_score: int
    dynamic_score: int
    final_score: int
    severity: str          # benign | low | medium | high | critical
    confidence: float      # 0.0 – 1.0
    reasons: List[str]
    recommended_action: str  # allow | warn | quarantine | block
    created_ts: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_id": self.message_id,
            "static_score": self.static_score,
            "dynamic_score": self.dynamic_score,
            "final_score": self.final_score,
            "severity": self.severity,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "recommended_action": self.recommended_action,
            "created_ts": self.created_ts,
        }
