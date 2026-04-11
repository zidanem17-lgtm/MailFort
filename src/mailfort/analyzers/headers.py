"""Header analyzer — SPF/DKIM/DMARC, routing anomalies, and envelope mismatch."""

import re
from typing import List

from ..models.message import NormalizedMessage
from ..models.findings import Finding, StaticAnalysisResult


class HeaderAnalyzer:

    CATEGORY = "headers"

    def run(self, msg: NormalizedMessage, result: StaticAnalysisResult) -> None:
        """Populate *result* with header-based findings."""
        h = msg.headers
        auth_results = h.get("authentication-results", "")

        self._check_spf(auth_results, result)
        self._check_dkim(auth_results, result)
        self._check_dmarc(auth_results, result)
        self._check_reply_to_mismatch(msg, result)
        self._check_display_name_mismatch(msg, result)
        self._check_return_path(msg, result)
        self._check_missing_message_id(h, result)
        self._check_received_chain(h, result)

    # ------------------------------------------------------------------

    def _check_spf(self, auth_results: str, result: StaticAnalysisResult) -> None:
        ar = auth_results.lower()
        if "spf=pass" in ar:
            return
        if "spf=fail" in ar or "spf=softfail" in ar or "spf=none" in ar:
            sev = "medium" if "spf=none" in ar else "high"
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="spf_fail",
                severity=sev,
                confidence=0.9,
                evidence={"authentication_results": auth_results[:300]},
                reason="SPF check did not pass",
            ))
        # If no SPF result at all — could be missing auth header
        elif "spf=" not in ar and auth_results:
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="spf_fail",
                severity="medium",
                confidence=0.6,
                evidence={"authentication_results": auth_results[:300]},
                reason="SPF result absent from authentication-results header",
            ))

    def _check_dkim(self, auth_results: str, result: StaticAnalysisResult) -> None:
        ar = auth_results.lower()
        if "dkim=pass" in ar:
            return
        if "dkim=fail" in ar or "dkim=none" in ar:
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="dkim_fail",
                severity="high",
                confidence=0.85,
                evidence={"authentication_results": auth_results[:300]},
                reason="DKIM signature is absent or invalid",
            ))

    def _check_dmarc(self, auth_results: str, result: StaticAnalysisResult) -> None:
        ar = auth_results.lower()
        if "dmarc=pass" in ar:
            return
        if "dmarc=fail" in ar or "dmarc=none" in ar:
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="dmarc_fail",
                severity="high",
                confidence=0.9,
                evidence={"authentication_results": auth_results[:300]},
                reason="DMARC policy evaluation failed or was not applicable",
            ))

    def _check_reply_to_mismatch(self, msg: NormalizedMessage, result: StaticAnalysisResult) -> None:
        if not msg.reply_to:
            return
        _, rt_addr = self._parse_addr(msg.reply_to)
        if not rt_addr:
            return
        rt_domain = rt_addr.split("@")[-1].lower() if "@" in rt_addr else ""
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

    def _check_display_name_mismatch(self, msg: NormalizedMessage, result: StaticAnalysisResult) -> None:
        display = msg.sender_display_name.lower()
        address = msg.sender_address.lower()
        if not display or not address:
            return
        # Flag if the display name contains an email address that differs
        # from the actual address (e.g. display = "someone@legit.com" but
        # the actual From address is attacker@evil.com)
        email_in_display = re.search(r"[\w.\-+]+@[\w.\-]+", display)
        if email_in_display:
            displayed_addr = email_in_display.group(0).lower()
            if displayed_addr != address:
                result.add_finding(Finding(
                    category=self.CATEGORY,
                    rule_id="display_name_mismatch",
                    severity="medium",
                    confidence=0.8,
                    evidence={
                        "display_name": msg.sender_display_name,
                        "sender_address": address,
                    },
                    reason="Display name contains an email address different from the actual sender",
                ))

    def _check_return_path(self, msg: NormalizedMessage, result: StaticAnalysisResult) -> None:
        if not msg.return_path:
            return
        _, rp_addr = self._parse_addr(msg.return_path)
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
                reason="Message-ID header is missing or empty",
            ))

    def _check_received_chain(self, headers: dict, result: StaticAnalysisResult) -> None:
        received = headers.get("received", "")
        # A single Received header for a multi-hop message is suspicious
        # (could indicate header stripping)
        if received and received.count("\n") == 0 and "via" not in received.lower():
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="received_chain_anomaly",
                severity="low",
                confidence=0.4,
                evidence={"received": received[:300]},
                reason="Received chain appears unusually short or truncated",
            ))

    @staticmethod
    def _parse_addr(value: str):
        import email.utils
        return email.utils.parseaddr(value)
