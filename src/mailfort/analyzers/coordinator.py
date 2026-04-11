"""Static analysis coordinator — orchestrates all analyzers and produces a StaticAnalysisResult."""

from typing import List, Optional

from ..models.message import NormalizedMessage
from ..models.findings import StaticAnalysisResult
from ..config import SCORING_WEIGHTS
from .headers import HeaderAnalyzer
from .sender import SenderAnalyzer
from .body import BodyAnalyzer
from .urls import URLAnalyzer
from .attachments import AttachmentAnalyzer
from .office_docs import OfficeDocAnalyzer
from .pdfs import PDFAnalyzer
from .archives import ArchiveAnalyzer


class StaticCoordinator:
    """Run all static analyzers in sequence and aggregate findings."""

    def __init__(self, trusted_domains: Optional[List[str]] = None) -> None:
        self.trusted_domains = trusted_domains or []
        self._headers = HeaderAnalyzer()
        self._sender = SenderAnalyzer()
        self._body = BodyAnalyzer()
        self._urls = URLAnalyzer()
        self._attachments = AttachmentAnalyzer()
        self._office = OfficeDocAnalyzer()
        self._pdf = PDFAnalyzer()
        self._archives = ArchiveAnalyzer()

    def run(self, msg: NormalizedMessage) -> StaticAnalysisResult:
        """Run all analyzers against *msg* and return an aggregated result."""
        result = StaticAnalysisResult()

        self._headers.run(msg, result)
        self._sender.run(msg, result, trusted_domains=self.trusted_domains)
        self._body.run(msg, result)
        self._urls.run(msg, result)
        self._attachments.run(msg, result)

        # Per-attachment deep inspection
        for att in msg.attachments:
            data = att.get("data_bytes")
            name = att.get("filename", "")
            if not data:
                continue
            if name.lower().endswith(".pdf"):
                self._pdf.analyse_bytes(data, name, result)
            elif name.lower().endswith((".zip", ".7z", ".rar")):
                self._archives.analyse_bytes(data, name, result)
            else:
                self._office.analyse_bytes(data, name, result)

        result.static_score = self._compute_score(result)
        return result

    # ------------------------------------------------------------------

    def _compute_score(self, result: StaticAnalysisResult) -> int:
        """Map findings to a 0–100 aggregate score using configured weights."""
        score = 0
        seen_rules: set = set()

        for finding in result.findings:
            rule_id = finding.rule_id
            if rule_id in seen_rules:
                continue
            seen_rules.add(rule_id)

            weight = SCORING_WEIGHTS.get(rule_id, 0)
            # Scale by confidence
            score += int(weight * finding.confidence)

        return min(score, 100)
