"""Verdict engine — combines static + dynamic evidence into a final Verdict."""

import time
from typing import List, Optional

from ..constants import SEVERITY_THRESHOLDS, SEVERITY_ORDER
from ..models.findings import StaticAnalysisResult
from ..models.verdict import Verdict, SandboxEvidence
from .scoring import score_static, score_dynamic


def _severity_from_score(score: int) -> str:
    for severity in reversed(SEVERITY_ORDER):
        if score >= SEVERITY_THRESHOLDS.get(severity, 0):
            return severity
    return "benign"


def _confidence_from_findings(result: StaticAnalysisResult) -> float:
    """Derive an aggregate confidence from all static findings."""
    if not result.findings:
        return 0.0
    avg = sum(f.confidence for f in result.findings) / len(result.findings)
    return round(avg, 2)


def build_verdict(
    message_id: str,
    static_result: StaticAnalysisResult,
    sandbox_results: Optional[List[SandboxEvidence]] = None,
) -> Verdict:
    """Build the final Verdict for a message.

    Hard-fail conditions (credential harvest, executable C2 callback, persistence)
    override any score and pin the verdict to critical/quarantine.
    """
    static_score = score_static(static_result)
    dynamic_score = score_dynamic(sandbox_results)

    # Collect all reasons
    reasons: List[str] = static_result.all_reasons()
    if sandbox_results:
        for ev in sandbox_results:
            reasons.extend(ev.reasons)

    # Check for hard-fail sandbox conditions
    hard_fail = False
    if sandbox_results:
        for ev in sandbox_results:
            if (
                ev.detected_credential_harvest
                or ev.detected_executable_network_callback
                or ev.detected_persistence
            ):
                hard_fail = True
                break

    if hard_fail:
        final_score = 95
        severity = "critical"
        recommended_action = "quarantine"
        confidence = 0.95
    else:
        final_score = min(static_score + dynamic_score, 100)
        severity = _severity_from_score(final_score)
        confidence = _confidence_from_findings(static_result)
        recommended_action = _default_action(severity)

    return Verdict(
        message_id=message_id,
        static_score=static_score,
        dynamic_score=dynamic_score,
        final_score=final_score,
        severity=severity,
        confidence=confidence,
        reasons=reasons,
        recommended_action=recommended_action,
        created_ts=time.time(),
    )


def _default_action(severity: str) -> str:
    mapping = {
        "critical": "quarantine",
        "high": "quarantine",
        "medium": "warn",
        "low": "allow",
        "benign": "allow",
    }
    return mapping.get(severity, "allow")
