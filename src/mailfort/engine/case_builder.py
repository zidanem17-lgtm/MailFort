"""Case builder — assembles a complete case bundle for a scanned message."""

import json
import time
from typing import Any, Dict, List, Optional

from ..models.message import NormalizedMessage
from ..models.findings import StaticAnalysisResult
from ..models.verdict import Verdict, SandboxEvidence
from ..models.policy import PolicyResult


def build_case(
    msg: NormalizedMessage,
    static_result: StaticAnalysisResult,
    verdict: Verdict,
    policy_result: PolicyResult,
    sandbox_results: Optional[List[SandboxEvidence]] = None,
) -> Dict[str, Any]:
    """Return a complete case dictionary suitable for JSON export or display."""
    return {
        "case_ts": time.time(),
        "message": {
            "message_id": msg.message_id,
            "thread_id": msg.thread_id,
            "provider": msg.provider,
            "sender": msg.sender,
            "sender_domain": msg.sender_domain,
            "subject": msg.subject,
            "date": msg.date_str,
            "labels": msg.labels,
            "body_sha256": msg.body_sha256,
            "html_sha256": msg.html_sha256,
            "attachment_count": len(msg.attachments),
        },
        "static_analysis": static_result.to_dict(),
        "sandbox_results": [ev.to_dict() for ev in (sandbox_results or [])],
        "verdict": verdict.to_dict(),
        "policy": policy_result.to_dict(),
    }


def format_case_summary(case: Dict[str, Any]) -> str:
    """Return a plain-text summary of a case bundle for CLI display."""
    v = case.get("verdict", {})
    p = case.get("policy", {})
    m = case.get("message", {})
    lines = [
        f"Message ID : {m.get('message_id')}",
        f"Sender     : {m.get('sender')}",
        f"Subject    : {m.get('subject')}",
        f"Provider   : {m.get('provider')}",
        f"Score      : {v.get('final_score')} (static {v.get('static_score')} + dynamic {v.get('dynamic_score')})",
        f"Severity   : {v.get('severity').upper()}",
        f"Confidence : {v.get('confidence', 0):.0%}",
        f"Action     : {p.get('action')}",
        "",
        "Reasons:",
    ]
    for reason in v.get("reasons", [])[:10]:
        lines.append(f"  - {reason}")
    return "\n".join(lines)
