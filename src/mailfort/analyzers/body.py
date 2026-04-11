"""Body analyzer — phishing language, login link detection, credential harvesting patterns."""

import re
from typing import List

from ..constants import PHISHING_KEYWORDS
from ..models.message import NormalizedMessage
from ..models.findings import Finding, StaticAnalysisResult

# Simple heuristic for login / credential pages linked in body
_LOGIN_PATTERNS = re.compile(
    r"(login|signin|sign-in|verify|account|secure|update|confirm|validate|webscr|ebayisapi)",
    re.IGNORECASE,
)

_CREDENTIAL_FORM_PATTERNS = re.compile(
    r'(type=["\']?password["\']?|name=["\']?pass|id=["\']?password)',
    re.IGNORECASE,
)


class BodyAnalyzer:

    CATEGORY = "body"

    def run(self, msg: NormalizedMessage, result: StaticAnalysisResult) -> None:
        text = (msg.body_text or "") + " " + (msg.body_html or "")
        text_lower = text.lower()

        matched_keywords = self._check_phishing_language(text_lower, result)
        self._check_login_links(msg.body_html or msg.body_text or "", result)
        self._check_credential_form_in_html(msg.body_html or "", result)

        result.body_analysis = {
            "phishing_keywords_matched": matched_keywords,
            "has_html": bool(msg.body_html),
            "body_length": len(text),
        }

    # ------------------------------------------------------------------

    def _check_phishing_language(
        self, text_lower: str, result: StaticAnalysisResult
    ) -> List[str]:
        matched = [kw for kw in PHISHING_KEYWORDS if kw in text_lower]
        if matched:
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="phishing_language",
                severity="medium",
                confidence=0.7,
                evidence={"matched_keywords": matched[:10]},
                reason=f"Body contains {len(matched)} phishing language indicator(s): {', '.join(matched[:3])}",
            ))
        return matched

    def _check_login_links(self, body: str, result: StaticAnalysisResult) -> None:
        """Flag when a link in the body suggests a login / credential page."""
        urls = re.findall(r"https?://[\w\-./:%?&=#+@]+", body)
        for url in urls:
            if _LOGIN_PATTERNS.search(url):
                result.contains_login_link = True
                result.add_finding(Finding(
                    category=self.CATEGORY,
                    rule_id="login_link",
                    severity="medium",
                    confidence=0.65,
                    evidence={"url": url[:200]},
                    reason=f"Body contains a link that resembles a credential or login page: {url[:80]}",
                ))
                break  # one finding is enough

    def _check_credential_form_in_html(self, html: str, result: StaticAnalysisResult) -> None:
        """Detect inline credential-harvesting forms embedded in HTML body."""
        if _CREDENTIAL_FORM_PATTERNS.search(html):
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="credential_form_in_body",
                severity="high",
                confidence=0.8,
                evidence={},
                reason="HTML body appears to contain a password input — possible inline credential harvest",
            ))
