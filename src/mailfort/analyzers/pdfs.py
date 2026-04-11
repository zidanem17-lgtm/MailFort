"""PDF analyzer — JavaScript, OpenAction, Launch, embedded files, form harvesting."""

import re

from ..models.findings import Finding, StaticAnalysisResult


# PDF keyword patterns
_PDF_JS_RE = re.compile(rb"/JS\b|/JavaScript\b", re.IGNORECASE)
_PDF_OPEN_ACTION_RE = re.compile(rb"/OpenAction\b", re.IGNORECASE)
_PDF_LAUNCH_RE = re.compile(rb"/Launch\b", re.IGNORECASE)
_PDF_EMBEDDED_FILE_RE = re.compile(rb"/EmbeddedFile\b", re.IGNORECASE)
_PDF_URI_RE = re.compile(rb"/URI\s*\(([^)]+)\)", re.IGNORECASE)
_PDF_SUBMIT_FORM_RE = re.compile(rb"/SubmitForm\b", re.IGNORECASE)
_PDF_ACROFORM_RE = re.compile(rb"/AcroForm\b", re.IGNORECASE)

# Suspicious URI patterns within PDFs
_SUSPICIOUS_URI_RE = re.compile(
    rb"https?://[\w\-./:%?&=]+",
    re.IGNORECASE,
)


class PDFAnalyzer:

    CATEGORY = "pdf"

    def analyse_bytes(
        self, data: bytes, filename: str, result: StaticAnalysisResult
    ) -> None:
        if not data or not data.startswith(b"%PDF"):
            return

        self._check_javascript(data, filename, result)
        self._check_open_action(data, filename, result)
        self._check_launch(data, filename, result)
        self._check_embedded_file(data, filename, result)
        self._check_form_harvesting(data, filename, result)

    # ------------------------------------------------------------------

    def _check_javascript(
        self, data: bytes, filename: str, result: StaticAnalysisResult
    ) -> None:
        if _PDF_JS_RE.search(data):
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="pdf_javascript",
                severity="high",
                confidence=0.9,
                evidence={"filename": filename},
                reason=f"'{filename}' contains embedded JavaScript — common malware vector",
            ))

    def _check_open_action(
        self, data: bytes, filename: str, result: StaticAnalysisResult
    ) -> None:
        if _PDF_OPEN_ACTION_RE.search(data):
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="pdf_open_action",
                severity="high",
                confidence=0.85,
                evidence={"filename": filename},
                reason=f"'{filename}' has an /OpenAction — code executes automatically when opened",
            ))

    def _check_launch(
        self, data: bytes, filename: str, result: StaticAnalysisResult
    ) -> None:
        if _PDF_LAUNCH_RE.search(data):
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="pdf_launch_action",
                severity="critical",
                confidence=0.9,
                evidence={"filename": filename},
                reason=f"'{filename}' contains a /Launch action — can execute arbitrary commands",
            ))

    def _check_embedded_file(
        self, data: bytes, filename: str, result: StaticAnalysisResult
    ) -> None:
        if _PDF_EMBEDDED_FILE_RE.search(data):
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="pdf_embedded_file",
                severity="medium",
                confidence=0.75,
                evidence={"filename": filename},
                reason=f"'{filename}' contains an embedded file — possible dropper",
            ))

    def _check_form_harvesting(
        self, data: bytes, filename: str, result: StaticAnalysisResult
    ) -> None:
        has_acroform = bool(_PDF_ACROFORM_RE.search(data))
        has_submit = bool(_PDF_SUBMIT_FORM_RE.search(data))
        if has_acroform and has_submit:
            urls = [
                m.group(0).decode("utf-8", errors="replace")
                for m in _SUSPICIOUS_URI_RE.finditer(data)
            ][:5]
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="pdf_form_harvest",
                severity="high",
                confidence=0.8,
                evidence={"filename": filename, "submission_urls": urls},
                reason=f"'{filename}' has a form with a remote submit action — possible credential harvesting PDF",
            ))
