"""Archive analyzer — nested archives, encrypted archives, recursive inspection."""

import io
import os
import zipfile
from typing import List, Optional

from ..constants import ARCHIVE_EXTENSIONS, HIGH_RISK_EXTENSIONS
from ..models.findings import Finding, StaticAnalysisResult


class ArchiveAnalyzer:

    CATEGORY = "archives"
    MAX_DEPTH = 3

    def analyse_bytes(
        self,
        data: bytes,
        filename: str,
        result: StaticAnalysisResult,
        depth: int = 0,
    ) -> None:
        if depth >= self.MAX_DEPTH or not data:
            return

        if not zipfile.is_zipfile(io.BytesIO(data)):
            return

        try:
            self._inspect_zip(data, filename, result, depth)
        except Exception:
            pass

    # ------------------------------------------------------------------

    def _inspect_zip(
        self,
        data: bytes,
        filename: str,
        result: StaticAnalysisResult,
        depth: int,
    ) -> None:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = zf.namelist()
                self._check_high_risk_entries(names, filename, result)

                for name in names:
                    ext = os.path.splitext(name)[1].lower()
                    if ext in ARCHIVE_EXTENSIONS:
                        try:
                            inner = zf.read(name)
                            if depth + 1 < self.MAX_DEPTH:
                                result.add_finding(Finding(
                                    category=self.CATEGORY,
                                    rule_id="nested_archive",
                                    severity="medium",
                                    confidence=0.7,
                                    evidence={"outer": filename, "inner": name},
                                    reason=f"Nested archive found: '{name}' inside '{filename}'",
                                ))
                                self.analyse_bytes(inner, name, result, depth + 1)
                        except Exception:
                            pass
        except zipfile.BadZipFile:
            # Encrypted or corrupt — already flagged by attachment analyzer entropy check
            pass
        except RuntimeError as e:
            if "encrypted" in str(e).lower() or "password" in str(e).lower():
                result.add_finding(Finding(
                    category=self.CATEGORY,
                    rule_id="encrypted_archive",
                    severity="medium",
                    confidence=0.8,
                    evidence={"filename": filename},
                    reason=f"'{filename}' is password-protected — contents cannot be inspected",
                ))

    def _check_high_risk_entries(
        self,
        names: List[str],
        archive_name: str,
        result: StaticAnalysisResult,
    ) -> None:
        risky = [
            n for n in names
            if os.path.splitext(n)[1].lower() in HIGH_RISK_EXTENSIONS
        ]
        if risky:
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="high_risk_extension",
                severity="high",
                confidence=0.9,
                evidence={"archive": archive_name, "risky_entries": risky[:10]},
                reason=f"Archive '{archive_name}' contains high-risk executable(s): {', '.join(risky[:3])}",
            ))
