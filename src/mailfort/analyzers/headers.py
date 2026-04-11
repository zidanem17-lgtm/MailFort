"""Header analyzer — SPF/DKIM/DMARC, routing anomalies, and envelope checks.

Authentication results are parsed with regex rather than simple substring
matching so that result tokens are extracted precisely
(e.g. ``spf=softfail`` vs ``spf=fail`` are weighted differently and
``spf=failtest`` is not a false positive).
"""

import re
from typing import Dict, List, Optional

from ..models.message import NormalizedMessage
from ..models.findings import Finding, StaticAnalysisResult


# Regex to pull individual result tokens from an Authentication-Results header.
# Handles both "mechanism=result" and "mechanism=result (comment)" forms.
_AUTH_TOKEN_RE = re.compile(
    r"(?<!\w)(spf|dkim|dmarc|arc|bimi)\s*=\s*(\w+)",
    re.IGNORECASE,
)

# Subject-line urgency signals
_URGENT_SUBJECT_RE = re.compile(
    r"\b(urgent|immediately|action required|verify now|account.*suspend|"
    r"limited time|expir|invoice|payment.*due|wire transfer|password.*expire|"
    r"security alert|unusual.*sign.in|confirm your)\b",
    re.IGNORECASE,
)

# All-caps subject (after stripping punctuation)
_ALL_CAPS_RE = re.compile(r"^[A-Z0-9\s\W]{8,}$")


def _parse_auth_results(header: str) -> Dict[str, str]:
    """Return a dict of {mechanism: result} from an Authentication-Results header."""
    results: Dict[str, str] = {}
    for m in _AUTH_TOKEN_RE.finditer(header):
        mech = m.group(1).lower()
        result = m.group(2).lower()
        # Keep the first occurrence of each mechanism (most authoritative)
        if mech not in results:
            results[mech] = result
    return results


class HeaderAnalyzer:

    CATEGORY = "headers"

    def run(self, msg: NormalizedMessage, result: StaticAnalysisResult) -> None:
        """Populate *result* with header-based findings."""
        h = msg.headers
        auth_header = h.get("authentication-results", "")
        auth = _parse_auth_results(auth_header)

        self._check_spf(auth, auth_header, result)
        self._check_dkim(auth, auth_header, result)
        self._check_dmarc(auth, auth_header, result)
        self._check_reply_to_mismatch(msg, result)
        self._check_display_name_mismatch(msg, result)
        self._check_return_path(msg, result)
        self._check_missing_message_id(h, result)
        self._check_received_chain(h, result)
        self._check_subject(msg.subject, result)

    # ------------------------------------------------------------------
    # Authentication checks (regex-based, not substring)
    # ------------------------------------------------------------------

    def _check_spf(
        self,
        auth: Dict[str, str],
        auth_header: str,
        result: StaticAnalysisResult,
    ) -> None:
        spf = auth.get("spf")
        if spf is None:
            # No SPF token at all — only flag if the header exists (missing header
            # means this MTA didn't check SPF, which is common on internal mail)
            if auth_header.strip():
                result.add_finding(Finding(
                    category=self.CATEGORY,
                    rule_id="spf_fail",
                    severity="low",
                    confidence=0.5,
                    evidence={"authentication_results": auth_header[:300]},
                    reason="SPF result absent from Authentication-Results header",
                ))
            return

        if spf == "pass":
            return

        severity_map = {
            "fail": ("high", 0.9),
            "softfail": ("medium", 0.8),
            "neutral": ("low", 0.5),
            "none": ("low", 0.55),
            "temperror": ("low", 0.4),
            "permerror": ("medium", 0.7),
        }
        severity, confidence = severity_map.get(spf, ("low", 0.4))
        result.add_finding(Finding(
            category=self.CATEGORY,
            rule_id="spf_fail",
            severity=severity,
            confidence=confidence,
            evidence={"spf_result": spf, "authentication_results": auth_header[:300]},
            reason=f"SPF result: {spf}",
        ))

    def _check_dkim(
        self,
        auth: Dict[str, str],
        auth_header: str,
        result: StaticAnalysisResult,
    ) -> None:
        dkim = auth.get("dkim")
        if dkim is None or dkim == "pass":
            return

        severity_map = {
            "fail": ("high", 0.9),
            "none": ("medium", 0.7),
            "policy": ("medium", 0.7),
            "neutral": ("low", 0.5),
            "temperror": ("low", 0.4),
            "permerror": ("medium", 0.7),
        }
        severity, confidence = severity_map.get(dkim, ("medium", 0.6))
        result.add_finding(Finding(
            category=self.CATEGORY,
            rule_id="dkim_fail",
            severity=severity,
            confidence=confidence,
            evidence={"dkim_result": dkim, "authentication_results": auth_header[:300]},
            reason=f"DKIM result: {dkim}",
        ))

    def _check_dmarc(
        self,
        auth: Dict[str, str],
        auth_header: str,
        result: StaticAnalysisResult,
    ) -> None:
        dmarc = auth.get("dmarc")
        if dmarc is None or dmarc == "pass":
            return

        severity_map = {
            "fail": ("high", 0.9),
            "none": ("medium", 0.65),
            "temperror": ("low", 0.4),
            "permerror": ("medium", 0.7),
        }
        severity, confidence = severity_map.get(dmarc, ("medium", 0.6))
        result.add_finding(Finding(
            category=self.CATEGORY,
            rule_id="dmarc_fail",
            severity=severity,
            confidence=confidence,
            evidence={"dmarc_result": dmarc, "authentication_results": auth_header[:300]},
            reason=f"DMARC result: {dmarc}",
        ))

    # ------------------------------------------------------------------
    # Envelope / routing checks
    # ------------------------------------------------------------------

    def _check_reply_to_mismatch(
        self, msg: NormalizedMessage, result: StaticAnalysisResult
    ) -> None:
        if not msg.reply_to:
            return
        _, rt_addr = _parse_addr(msg.reply_to)
        if not rt_addr or "@" not in rt_addr:
            return
        rt_domain = rt_addr.split("@")[-1].lower()
        sender_domain = msg.sender_domain.lower()
        if rt_domain and sender_domain and rt_domain != sender_domain:
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="reply_to_mismatch",
                severity="medium",
                confidence=0.75,
                evidence={
                    "sender_domain": sender_domain,
                    "reply_to_domain": rt_domain,
                    "reply_to": msg.reply_to,
                },
                reason=f"Reply-To domain ({rt_domain}) differs from sender domain ({sender_domain})",
            ))

    def _check_display_name_mismatch(
        self, msg: NormalizedMessage, result: StaticAnalysisResult
    ) -> None:
        """Flag when the display name embeds an email address different from the real sender.

        Example: From: "support@paypal.com" <attacker@evil.com>
        """
        display = msg.sender_display_name.lower()
        address = msg.sender_address.lower()
        if not display or not address:
            return
        email_in_display = re.search(r"[\w.\-+]+@[\w.\-]+\.\w+", display)
        if email_in_display:
            displayed_addr = email_in_display.group(0).lower()
            if displayed_addr != address:
                result.add_finding(Finding(
                    category=self.CATEGORY,
                    rule_id="display_name_mismatch",
                    severity="high",
                    confidence=0.85,
                    evidence={
                        "display_name": msg.sender_display_name,
                        "sender_address": address,
                        "embedded_address": displayed_addr,
                    },
                    reason=(
                        f"Display name contains '{displayed_addr}' but actual "
                        f"sender address is '{address}'"
                    ),
                ))

    def _check_return_path(
        self, msg: NormalizedMessage, result: StaticAnalysisResult
    ) -> None:
        if not msg.return_path:
            return
        _, rp_addr = _parse_addr(msg.return_path)
        if not rp_addr or "@" not in rp_addr:
            return
        rp_domain = rp_addr.split("@")[-1].lower()
        sender_domain = msg.sender_domain.lower()
        if rp_domain and sender_domain and rp_domain != sender_domain:
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="suspicious_return_path",
                severity="low",
                confidence=0.6,
                evidence={
                    "return_path": msg.return_path,
                    "return_path_domain": rp_domain,
                    "sender_domain": sender_domain,
                },
                reason=f"Return-Path domain ({rp_domain}) does not match sender domain ({sender_domain})",
            ))

    def _check_missing_message_id(self, headers: dict, result: StaticAnalysisResult) -> None:
        if not headers.get("message-id", "").strip():
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="missing_message_id",
                severity="low",
                confidence=0.5,
                evidence={},
                reason="Message-ID header is missing — unusual for legitimate senders",
            ))

    def _check_received_chain(self, headers: dict, result: StaticAnalysisResult) -> None:
        """Flag an unusually thin Received chain.

        Legitimate multi-hop messages typically show several Received headers.
        A single-hop with no relay information may indicate header stripping.
        """
        received = headers.get("received", "")
        if not received:
            return
        hop_count = received.count("by ") + received.count("from ")
        if hop_count <= 1 and "via" not in received.lower():
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="received_chain_anomaly",
                severity="low",
                confidence=0.4,
                evidence={"received_snippet": received[:200]},
                reason="Received chain is unusually short — possible header stripping",
            ))

    # ------------------------------------------------------------------
    # Subject-line heuristics
    # ------------------------------------------------------------------

    def _check_subject(self, subject: str, result: StaticAnalysisResult) -> None:
        if not subject:
            return

        # All-caps subject
        subj_stripped = re.sub(r"[^A-Za-z0-9 ]", "", subject)
        if subj_stripped and _ALL_CAPS_RE.match(subj_stripped):
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="all_caps_subject",
                severity="low",
                confidence=0.5,
                evidence={"subject": subject},
                reason="Subject line is entirely uppercase — common urgency tactic",
            ))

        # Urgency keywords in subject
        if _URGENT_SUBJECT_RE.search(subject):
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="urgent_subject",
                severity="medium",
                confidence=0.65,
                evidence={"subject": subject},
                reason=f"Subject line uses urgency language: '{subject[:80]}'",
            ))


# ---------------------------------------------------------------------------
# Module-level helper (avoids per-call import overhead)
# ---------------------------------------------------------------------------

def _parse_addr(value: str):
    return email.utils.parseaddr(value)


# Keep the import available for the static method call pattern elsewhere
import email.utils  # noqa: E402 — after function def is fine
