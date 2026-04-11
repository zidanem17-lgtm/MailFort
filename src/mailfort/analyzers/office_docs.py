"""Office document analyzer — macro indicators, external template refs, auto-open actions."""

import re
from typing import Optional

from ..models.findings import Finding, StaticAnalysisResult


# Binary signatures for OLE compound documents (legacy Office)
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# Indicators commonly found in macro-enabled documents
_MACRO_STRINGS = [
    b"VBA",
    b"AutoOpen",
    b"AutoExec",
    b"Document_Open",
    b"Workbook_Open",
    b"Shell(",
    b"WScript.Shell",
    b"CreateObject",
    b"PowerShell",
    b"cmd.exe",
    b"mshta",
    b"regsvr32",
    b"certutil",
]

# External template reference pattern (for remote-template phishing)
_TEMPLATE_REF_RE = re.compile(
    rb"Target=\"(https?://[^\"]+)\".*?TargetMode=\"External\"",
    re.DOTALL | re.IGNORECASE,
)

_AUTO_OPEN_RE = re.compile(
    rb"(AutoOpen|AutoExec|Document_Open|Workbook_Open)",
    re.IGNORECASE,
)


class OfficeDocAnalyzer:

    CATEGORY = "office"

    def analyse_bytes(
        self,
        data: bytes,
        filename: str,
        result: StaticAnalysisResult,
    ) -> None:
        """Analyse raw bytes of an Office document."""
        if not data:
            return

        self._check_ole_macros(data, filename, result)
        self._check_external_template(data, filename, result)
        self._check_auto_open(data, filename, result)

    # ------------------------------------------------------------------

    def _check_ole_macros(
        self, data: bytes, filename: str, result: StaticAnalysisResult
    ) -> None:
        """Detect macro code in OLE (legacy .doc/.xls) documents."""
        if not data.startswith(_OLE_MAGIC):
            return
        found = [s.decode("latin-1") for s in _MACRO_STRINGS if s in data]
        if found:
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="macro_indicator",
                severity="critical",
                confidence=0.9,
                evidence={"filename": filename, "indicators": found[:10]},
                reason=f"'{filename}' contains macro code indicators: {', '.join(found[:5])}",
            ))

    def _check_external_template(
        self, data: bytes, filename: str, result: StaticAnalysisResult
    ) -> None:
        """Detect remote template injection (TargetMode=External in relationships)."""
        matches = _TEMPLATE_REF_RE.findall(data)
        if matches:
            urls = [m.decode("utf-8", errors="replace") for m in matches[:3]]
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="external_template_ref",
                severity="critical",
                confidence=0.95,
                evidence={"filename": filename, "template_urls": urls},
                reason=f"'{filename}' references an external template — remote code injection risk",
            ))

    def _check_auto_open(
        self, data: bytes, filename: str, result: StaticAnalysisResult
    ) -> None:
        if _AUTO_OPEN_RE.search(data):
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="auto_open_action",
                severity="critical",
                confidence=0.88,
                evidence={"filename": filename},
                reason=f"'{filename}' has an Auto-Open/Document-Open macro trigger",
            ))
