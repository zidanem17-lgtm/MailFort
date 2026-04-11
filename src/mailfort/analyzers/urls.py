"""URL analyzer — punycode, shorteners, raw IPs, lookalikes, suspicious TLDs."""

import re
import ipaddress
from typing import List, Optional
from urllib.parse import urlparse, parse_qs

import tldextract

from ..constants import URL_SHORTENERS, SUSPICIOUS_TLDS
from ..models.message import NormalizedMessage
from ..models.findings import Finding, StaticAnalysisResult
from ..models.artifact import URLArtifact

URL_RE = re.compile(r"https?://[\w\-\.\/:?&=%#@+~]+", re.IGNORECASE)
ANCHOR_RE = re.compile(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)


class URLAnalyzer:

    CATEGORY = "urls"

    def run(self, msg: NormalizedMessage, result: StaticAnalysisResult) -> None:
        body = (msg.body_text or "") + " " + (msg.body_html or "")
        plain_urls = URL_RE.findall(body)
        anchor_pairs = ANCHOR_RE.findall(msg.body_html or "")

        # Build anchor text map: href → display text
        anchor_map = {}
        for href, text in anchor_pairs:
            stripped = re.sub(r"<[^>]+>", "", text).strip()
            anchor_map[href.strip()] = stripped

        seen: set = set()
        artifacts: List[URLArtifact] = []

        for url in plain_urls:
            if url in seen:
                continue
            seen.add(url)
            artifact = self._analyse_url(url, anchor_map.get(url), result)
            if artifact:
                artifacts.append(artifact)

        result.urls = [a.to_dict() for a in artifacts]

    # ------------------------------------------------------------------

    def _analyse_url(
        self,
        url: str,
        anchor_text: Optional[str],
        result: StaticAnalysisResult,
    ) -> Optional[URLArtifact]:
        try:
            parsed = urlparse(url)
        except Exception:
            return None

        host = parsed.hostname or ""
        extracted = tldextract.extract(url)
        registered_domain = extracted.registered_domain or host

        artifact = URLArtifact(
            original_url=url,
            normalized_url=url.lower(),
            registered_domain=registered_domain,
            anchor_text=anchor_text,
        )

        self._check_punycode(host, artifact, result)
        self._check_raw_ip(host, artifact, result)
        self._check_shortener(registered_domain, artifact, result)
        self._check_suspicious_tld(extracted.suffix, artifact, result)
        self._check_anchor_mismatch(url, anchor_text, artifact, result)
        self._check_excessive_query_params(parsed, result)

        return artifact

    def _check_punycode(self, host: str, artifact: URLArtifact, result: StaticAnalysisResult) -> None:
        if "xn--" in host:
            artifact.is_punycode = True
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="punycode_domain",
                severity="high",
                confidence=0.9,
                evidence={"domain": host, "url": artifact.original_url[:200]},
                reason=f"URL uses a punycode (internationalised) domain: {host}",
            ))

    def _check_raw_ip(self, host: str, artifact: URLArtifact, result: StaticAnalysisResult) -> None:
        try:
            ipaddress.ip_address(host)
            artifact.is_raw_ip = True
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="raw_ip_url",
                severity="high",
                confidence=0.85,
                evidence={"ip": host, "url": artifact.original_url[:200]},
                reason=f"URL references a raw IP address ({host}) rather than a domain",
            ))
        except ValueError:
            pass

    def _check_shortener(
        self, domain: str, artifact: URLArtifact, result: StaticAnalysisResult
    ) -> None:
        if domain.lower() in URL_SHORTENERS:
            artifact.is_shortener = True
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="url_shortener",
                severity="medium",
                confidence=0.8,
                evidence={"domain": domain, "url": artifact.original_url[:200]},
                reason=f"URL uses a known shortener service ({domain}) — final destination hidden",
            ))

    def _check_suspicious_tld(
        self, suffix: str, artifact: URLArtifact, result: StaticAnalysisResult
    ) -> None:
        if not suffix:
            return
        tld = f".{suffix}" if not suffix.startswith(".") else suffix
        if tld.lower() in SUSPICIOUS_TLDS:
            artifact.suspicious_tld = True
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="suspicious_tld",
                severity="medium",
                confidence=0.65,
                evidence={"tld": tld, "url": artifact.original_url[:200]},
                reason=f"URL uses a TLD ({tld}) with a high abuse rate",
            ))

    def _check_anchor_mismatch(
        self,
        url: str,
        anchor_text: Optional[str],
        artifact: URLArtifact,
        result: StaticAnalysisResult,
    ) -> None:
        if not anchor_text:
            return
        # If anchor text itself looks like a URL that differs from href
        possible_url = anchor_text.strip()
        if possible_url.startswith("http") and possible_url.rstrip("/") != url.rstrip("/"):
            anchor_domain = tldextract.extract(possible_url).registered_domain
            href_domain = artifact.registered_domain
            if anchor_domain and href_domain and anchor_domain != href_domain:
                artifact.anchor_text_mismatch = True
                result.add_finding(Finding(
                    category=self.CATEGORY,
                    rule_id="anchor_text_mismatch",
                    severity="high",
                    confidence=0.85,
                    evidence={
                        "displayed_url": possible_url[:200],
                        "actual_url": url[:200],
                    },
                    reason=f"Link text shows '{anchor_domain}' but href points to '{href_domain}'",
                ))

    def _check_excessive_query_params(self, parsed, result: StaticAnalysisResult) -> None:
        qs = parse_qs(parsed.query)
        if len(qs) > 8:
            result.add_finding(Finding(
                category=self.CATEGORY,
                rule_id="excessive_query_params",
                severity="low",
                confidence=0.4,
                evidence={"param_count": len(qs)},
                reason=f"URL has an unusually large number of query parameters ({len(qs)})",
            ))
