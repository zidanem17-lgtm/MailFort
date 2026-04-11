"""Static analysis result models."""

from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class Finding:
    """A single rule match produced by a static analyzer."""

    category: str       # headers | sender | body | urls | attachments | office | pdf
    rule_id: str        # e.g. "spf_fail", "punycode_domain"
    severity: str       # benign | low | medium | high | critical
    confidence: float   # 0.0 – 1.0
    evidence: Dict[str, Any]
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "reason": self.reason,
        }


@dataclass
class StaticAnalysisResult:
    """Aggregate output of all static analyzers for a single message."""

    findings: List[Finding] = field(default_factory=list)
    urls: List[Dict[str, Any]] = field(default_factory=list)
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    sender_profile: Dict[str, Any] = field(default_factory=dict)
    header_analysis: Dict[str, Any] = field(default_factory=dict)
    body_analysis: Dict[str, Any] = field(default_factory=dict)
    static_score: int = 0

    # Gate flags used by the detonation eligibility check
    has_critical_rule: bool = False
    contains_login_link: bool = False
    contains_executable_or_macro_attachment: bool = False

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        if finding.severity == "critical":
            self.has_critical_rule = True

    def all_reasons(self) -> List[str]:
        return [f.reason for f in self.findings]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "urls": self.urls,
            "attachments": self.attachments,
            "sender_profile": self.sender_profile,
            "header_analysis": self.header_analysis,
            "body_analysis": self.body_analysis,
            "static_score": self.static_score,
            "has_critical_rule": self.has_critical_rule,
            "contains_login_link": self.contains_login_link,
            "contains_executable_or_macro_attachment": self.contains_executable_or_macro_attachment,
        }
