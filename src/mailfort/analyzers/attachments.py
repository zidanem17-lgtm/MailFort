"""Attachment analyzer — MIME detection, entropy, extension mismatch, high-risk types."""

import base64
import hashlib
import math
import os
from collections import defaultdict
from typing import Any, Dict, List, Optional

from ..constants import (
    HIGH_RISK_EXTENSIONS,
    MACRO_EXTENSIONS,
    ARCHIVE_EXTENSIONS,
    HIGH_RISK_MIME_TYPES,
)
from ..config import DEFAULT_ENTROPY_THRESHOLD
from ..models.message import NormalizedMessage
from ..models.findings import Finding, StaticAnalysisResult
from ..models.artifact import AttachmentArtifact

try:
    import magic as libmagic
    _MAGIC_AVAILABLE = True
except ImportError:
    _MAGIC_AVAILABLE = False


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: Dict[int, int] = defaultdict(int)
    for b in data:
        freq[b] += 1
    ent = 0.0
    n = len(data)
    for count in freq.values():
        p = count / n
        ent -= p * math.log2(p)
    return ent


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _detect_mime(data: bytes) -> str:
    if _MAGIC_AVAILABLE and data:
        try:
            return libmagic.from_buffer(data, mime=True)
        except Exception:
            pass
    return "application/octet-stream"


class AttachmentAnalyzer:

    CATEGORY = "attachments"

    def run(self, msg: NormalizedMessage, result: StaticAnalysisResult) -> None:
        artifacts: List[AttachmentArtifact] = []

        for part in msg.attachments:
            filename = part.get("filename", "")
            declared_mime = part.get("declared_mime", "application/octet-stream")
            data_bytes: Optional[bytes] = part.get("data_bytes")

            if not data_bytes:
                continue

            ext = os.path.splitext(filename)[1].lower() if filename else ""
            detected_mime = _detect_mime(data_bytes)
            ent = _entropy(data_bytes)
            sha = _sha256(data_bytes)
            size = len(data_bytes)

            artifact = AttachmentArtifact(
                filename=filename,
                sha256=sha,
                mime_type=detected_mime,
                declared_mime=declared_mime,
                extension=ext,
                size_bytes=size,
                entropy=ent,
                is_archive=ext in ARCHIVE_EXTENSIONS,
                is_macro_doc=ext in MACRO_EXTENSIONS,
                is_pdf=(ext == ".pdf" or detected_mime == "application/pdf"),
            )

            self._check_high_risk_extension(ext, filename, artifact, result)
            self._check_mime_mismatch(ext, detected_mime, declared_mime, filename, artifact, result)
            self._check_entropy(ent, filename, artifact, result)
            self._check_encrypted_archive(ext, ent, filename, artifact, result)
            self._check_macro_doc(ext, artifact, result)

            artifacts.append(artifact)

        if any(
            a.is_macro_doc or a.high_risk
            for a in artifacts
        ):
            result.contains_executable_or_macro_attachment = True

        result.attachments = [a.to_dict() for a in artifacts]

    # ------------------------------------------------------------------

    def _check_high_risk_extension(
        self,
        ext: str,
        filename: str,
        artifact: AttachmentArtifact,
        result: StaticAnalysisResult,
    ) -> None:
        if ext in HIGH_RISK_EXTENSIONS:
            artifact.high_risk = True
            artifact.risk_flags.append("high_risk_extension")
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="high_risk_extension",
                severity="high",
                confidence=0.9,
                evidence={"filename": filename, "extension": ext},
                reason=f"Attachment '{filename}' has a high-risk executable extension ({ext})",
            ))

    def _check_mime_mismatch(
        self,
        ext: str,
        detected: str,
        declared: str,
        filename: str,
        artifact: AttachmentArtifact,
        result: StaticAnalysisResult,
    ) -> None:
        # Only flag when the detected MIME is dangerous but the extension looks benign
        if detected in HIGH_RISK_MIME_TYPES and ext not in HIGH_RISK_EXTENSIONS:
            artifact.extension_mismatch = True
            artifact.high_risk = True
            artifact.risk_flags.append("extension_mismatch")
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="extension_mismatch",
                severity="high",
                confidence=0.85,
                evidence={
                    "filename": filename,
                    "extension": ext,
                    "declared_mime": declared,
                    "detected_mime": detected,
                },
                reason=f"Attachment '{filename}' appears to be '{detected}' despite having extension '{ext}'",
            ))

    def _check_entropy(
        self,
        ent: float,
        filename: str,
        artifact: AttachmentArtifact,
        result: StaticAnalysisResult,
    ) -> None:
        if ent >= DEFAULT_ENTROPY_THRESHOLD:
            artifact.risk_flags.append("high_entropy")
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="steg_indicator",
                severity="medium",
                confidence=0.7,
                evidence={"filename": filename, "entropy": round(ent, 4)},
                reason=f"Attachment '{filename}' has very high entropy ({ent:.2f}) — may be encrypted or obfuscated",
            ))

    def _check_encrypted_archive(
        self,
        ext: str,
        ent: float,
        filename: str,
        artifact: AttachmentArtifact,
        result: StaticAnalysisResult,
    ) -> None:
        if ext in ARCHIVE_EXTENSIONS and ent >= DEFAULT_ENTROPY_THRESHOLD:
            artifact.is_encrypted_archive = True
            artifact.risk_flags.append("encrypted_archive")
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="encrypted_archive",
                severity="medium",
                confidence=0.75,
                evidence={"filename": filename, "entropy": round(ent, 4)},
                reason=f"Archive '{filename}' appears encrypted (high entropy) — contents cannot be inspected statically",
            ))

    def _check_macro_doc(
        self,
        ext: str,
        artifact: AttachmentArtifact,
        result: StaticAnalysisResult,
    ) -> None:
        if ext in MACRO_EXTENSIONS:
            artifact.is_macro_doc = True
            artifact.risk_flags.append("macro_capable_extension")
            result.contains_executable_or_macro_attachment = True
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="macro_indicator",
                severity="high",
                confidence=0.8,
                evidence={"filename": artifact.filename, "extension": ext},
                reason=f"Attachment '{artifact.filename}' uses a macro-capable Office format",
            ))
