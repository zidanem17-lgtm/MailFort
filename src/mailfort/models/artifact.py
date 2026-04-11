"""Artifact models for URLs and attachments extracted from messages."""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


@dataclass
class URLArtifact:
    """A URL extracted from a message body or header."""

    original_url: str
    normalized_url: str
    registered_domain: str

    is_punycode: bool = False
    is_shortener: bool = False
    is_raw_ip: bool = False
    is_lookalike: bool = False
    is_brand_impersonation: bool = False
    suspicious_tld: bool = False
    anchor_text: Optional[str] = None
    anchor_text_mismatch: bool = False
    redirect_count: int = 0
    final_url: Optional[str] = None
    final_domain: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_url": self.original_url,
            "normalized_url": self.normalized_url,
            "registered_domain": self.registered_domain,
            "is_punycode": self.is_punycode,
            "is_shortener": self.is_shortener,
            "is_raw_ip": self.is_raw_ip,
            "is_lookalike": self.is_lookalike,
            "is_brand_impersonation": self.is_brand_impersonation,
            "suspicious_tld": self.suspicious_tld,
            "anchor_text": self.anchor_text,
            "anchor_text_mismatch": self.anchor_text_mismatch,
            "redirect_count": self.redirect_count,
            "final_url": self.final_url,
            "final_domain": self.final_domain,
            "evidence": self.evidence,
        }


@dataclass
class AttachmentArtifact:
    """An attachment extracted from a message."""

    filename: str
    sha256: str
    mime_type: str          # detected MIME (via libmagic)
    declared_mime: str      # MIME from the Content-Type header
    extension: str          # lowercase file extension
    size_bytes: int
    entropy: float

    is_archive: bool = False
    is_macro_doc: bool = False
    is_pdf: bool = False
    extension_mismatch: bool = False
    high_risk: bool = False
    is_encrypted_archive: bool = False
    is_nested_archive: bool = False
    has_macros: bool = False
    has_js: bool = False
    risk_flags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "sha256": self.sha256,
            "mime_type": self.mime_type,
            "declared_mime": self.declared_mime,
            "extension": self.extension,
            "size_bytes": self.size_bytes,
            "entropy": round(self.entropy, 4),
            "is_archive": self.is_archive,
            "is_macro_doc": self.is_macro_doc,
            "is_pdf": self.is_pdf,
            "extension_mismatch": self.extension_mismatch,
            "high_risk": self.high_risk,
            "is_encrypted_archive": self.is_encrypted_archive,
            "is_nested_archive": self.is_nested_archive,
            "has_macros": self.has_macros,
            "has_js": self.has_js,
            "risk_flags": self.risk_flags,
        }
