"""Sender analyzer — domain baselines, lookalike detection, brand impersonation.

Checks both the display name *and* the subject line for brand references,
since attackers increasingly place the brand name only in the subject
(e.g. "RE: Your Microsoft account" from a random domain).
"""

import difflib
import re
from typing import Dict, List, Optional, Set

import tldextract

from ..constants import KNOWN_BRANDS
from ..models.message import NormalizedMessage
from ..models.findings import Finding, StaticAnalysisResult


# ---------------------------------------------------------------------------
# Homoglyph normalisation for lookalike detection
# ---------------------------------------------------------------------------

# Multi-char substitutions must come before single-char ones to avoid
# partial replacement (e.g. "rn" → "m" before "r" → anything).
_HOMOGLYPHS_MULTI: List[tuple] = [
    ("rn", "m"), ("vv", "w"), ("cl", "d"), ("ii", "n"),
]
_HOMOGLYPHS_SINGLE: Dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "6": "g", "7": "t", "8": "b",
}


def _normalise_domain(domain: str) -> str:
    """Collapse common homoglyphs so brand comparisons are glyph-blind."""
    d = domain.lower()
    for fake, real in _HOMOGLYPHS_MULTI:
        d = d.replace(fake, real)
    for fake, real in _HOMOGLYPHS_SINGLE.items():
        d = d.replace(fake, real)
    return d


# ---------------------------------------------------------------------------
# Impersonation role keywords (boost confidence when combined with brand name)
# ---------------------------------------------------------------------------

_IMPERSONATION_ROLES = re.compile(
    r"\b(support|security|helpdesk|team|service|noreply|no.reply|"
    r"billing|accounts?|admin|alert|notification|verify|update)\b",
    re.IGNORECASE,
)


def _brand_in_text(text: str) -> Optional[str]:
    """Return the first known brand found in *text*, or None."""
    tl = text.lower()
    for brand in KNOWN_BRANDS:
        if brand in tl:
            return brand
    return None


class SenderAnalyzer:

    CATEGORY = "sender"

    def run(
        self,
        msg: NormalizedMessage,
        result: StaticAnalysisResult,
        trusted_domains: Optional[List[str]] = None,
    ) -> None:
        domain = msg.sender_domain.lower()

        self._check_brand_impersonation(msg, domain, result)
        self._check_lookalike(domain, trusted_domains or [], result)
        self._check_freemail_impersonation(msg.sender_display_name, domain, result)

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
        msg: NormalizedMessage,
        domain: str,
        result: StaticAnalysisResult,
    ) -> None:
        """Flag when the display name *or* the subject references a known brand
        but the sending domain does not belong to that brand.

        Attackers often rely on:
          - Display name: "PayPal Security" from attacker@evil.com
          - Subject only: "RE: Your Microsoft account" from random-domain.com
        """
        normalised_domain = _normalise_domain(domain)

        # Gather all text surfaces that could carry brand names
        surfaces: Dict[str, str] = {
            "display_name": msg.sender_display_name,
            "subject": msg.subject or "",
        }

        for surface_name, text in surfaces.items():
            brand = _brand_in_text(text)
            if brand is None:
                continue

            # Check whether the sending domain legitimately belongs to the brand
            brand_normalised = _normalise_domain(brand)
            domain_without_tld = normalised_domain.split(".")[0]
            if brand_normalised in domain_without_tld or domain_without_tld in brand_normalised:
                continue  # legitimate sender (e.g. microsoft.com, google.com)

            # Raise confidence when an impersonation role keyword is also present
            role_match = bool(_IMPERSONATION_ROLES.search(text))
            confidence = 0.9 if role_match else 0.8

            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="brand_impersonation",
                severity="high",
                confidence=confidence,
                evidence={
                    "surface": surface_name,
                    "text": text[:120],
                    "sender_domain": domain,
                    "impersonated_brand": brand,
                    "role_keyword_present": role_match,
                },
                reason=(
                    f"{surface_name.replace('_', ' ').title()} references "
                    f"'{brand}' but message is sent from '{domain}'"
                ),
            ))
            return  # one finding per message

    def _check_lookalike(
        self,
        domain: str,
        trusted_domains: List[str],
        result: StaticAnalysisResult,
    ) -> None:
        """Detect domains that closely resemble trusted or known-brand domains
        using sequence similarity after homoglyph normalisation.
        """
        if not domain:
            return

        pool: List[str] = list(trusted_domains)
        for brand in KNOWN_BRANDS:
            pool.append(f"{brand}.com")

        normalised_sender = _normalise_domain(domain)
        best_ratio = 0.0
        best_candidate = ""

        for candidate in pool:
            candidate_clean = candidate.lower().lstrip("@")
            if candidate_clean == domain:
                return  # exact match — definitely not a lookalike

            ratio = difflib.SequenceMatcher(
                None,
                normalised_sender,
                _normalise_domain(candidate_clean),
            ).ratio()

            if ratio > best_ratio:
                best_ratio = ratio
                best_candidate = candidate_clean

        if best_ratio >= 0.85 and best_candidate:
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="lookalike_domain",
                severity="high",
                confidence=round(best_ratio, 2),
                evidence={
                    "sender_domain": domain,
                    "similar_to": best_candidate,
                    "similarity": round(best_ratio, 2),
                },
                reason=(
                    f"Sender domain '{domain}' closely resembles "
                    f"'{best_candidate}' ({best_ratio:.0%} similar)"
                ),
            ))

    def _check_freemail_impersonation(
        self,
        display_name: str,
        domain: str,
        result: StaticAnalysisResult,
    ) -> None:
        """Flag when a corporate-sounding display name is paired with a
        free-mail provider domain (e.g. 'Microsoft Support' from gmail.com).
        """
        _FREEMAIL_DOMAINS: Set[str] = {
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
            "aol.com", "protonmail.com", "icloud.com", "mail.com",
            "yandex.com", "zoho.com",
        }
        if domain not in _FREEMAIL_DOMAINS:
            return

        brand = _brand_in_text(display_name)
        if brand is None:
            return

        result.add_finding(Finding(
            category=self.CATEGORY,
            rule_id="freemail_brand_impersonation",
            severity="high",
            confidence=0.88,
            evidence={
                "display_name": display_name,
                "freemail_domain": domain,
                "impersonated_brand": brand,
            },
            reason=(
                f"'{brand}' brand referenced in display name but sender uses "
                f"free-mail provider '{domain}'"
            ),
        ))
