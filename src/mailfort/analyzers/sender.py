"""Sender analyzer — domain baselines, lookalike detection, brand impersonation."""

import difflib
import re
from typing import Dict, Optional

import tldextract

from ..constants import KNOWN_BRANDS
from ..models.message import NormalizedMessage
from ..models.findings import Finding, StaticAnalysisResult


# Homoglyph substitutions for lookalike detection
_HOMOGLYPHS: Dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "6": "g", "7": "t", "8": "b", "rn": "m", "vv": "w",
    "cl": "d", "ii": "n",
}


def _normalise_domain(domain: str) -> str:
    """Strip common homoglyphs for brand comparison."""
    d = domain.lower()
    for fake, real in _HOMOGLYPHS.items():
        d = d.replace(fake, real)
    return d


class SenderAnalyzer:

    CATEGORY = "sender"

    def run(
        self,
        msg: NormalizedMessage,
        result: StaticAnalysisResult,
        trusted_domains: Optional[list] = None,
    ) -> None:
        domain = msg.sender_domain.lower()

        self._check_brand_impersonation(domain, msg.sender_display_name, result)
        self._check_lookalike(domain, trusted_domains or [], result)

        result.sender_profile = {
            "sender": msg.sender,
            "sender_address": msg.sender_address,
            "sender_domain": domain,
            "display_name": msg.sender_display_name,
            "reply_to": msg.reply_to,
        }

    # ------------------------------------------------------------------

    def _check_brand_impersonation(
        self,
        domain: str,
        display_name: str,
        result: StaticAnalysisResult,
    ) -> None:
        """Flag when the display name references a known brand but the
        sending domain does not belong to that brand."""
        display_lower = display_name.lower()
        normalised = _normalise_domain(domain)
        for brand in KNOWN_BRANDS:
            if brand not in display_lower:
                continue
            # Check if the domain actually belongs to the brand
            # (e.g. microsoft.com, google.com)
            if brand in normalised.replace(".", ""):
                continue  # legitimate sender
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="brand_impersonation",
                severity="high",
                confidence=0.85,
                evidence={
                    "display_name": display_name,
                    "sender_domain": domain,
                    "impersonated_brand": brand,
                },
                reason=f"Display name references '{brand}' but sending domain is '{domain}'",
            ))
            return  # one finding per message is enough

    def _check_lookalike(
        self,
        domain: str,
        trusted_domains: list,
        result: StaticAnalysisResult,
    ) -> None:
        """Detect domains that closely resemble trusted or known-brand domains."""
        if not domain:
            return

        # Build the comparison pool from known brands + caller-supplied domains
        pool = list(trusted_domains)
        for brand in KNOWN_BRANDS:
            pool.append(f"{brand}.com")

        normalised_sender = _normalise_domain(domain)

        for candidate in pool:
            candidate_clean = candidate.lower().lstrip("@")
            if candidate_clean == domain:
                continue  # exact match — legitimate
            ratio = difflib.SequenceMatcher(
                None, normalised_sender, _normalise_domain(candidate_clean)
            ).ratio()
            if ratio >= 0.85:
                result.add_finding(Finding(
                    category=self.CATEGORY,
                    rule_id="lookalike_domain",
                    severity="high",
                    confidence=round(ratio, 2),
                    evidence={
                        "sender_domain": domain,
                        "similar_to": candidate_clean,
                        "similarity": round(ratio, 2),
                    },
                    reason=f"Sender domain '{domain}' closely resembles '{candidate_clean}' (similarity {ratio:.0%})",
                ))
                return  # report the closest match only
