"""Sandbox orchestrator — detonation gate and evidence aggregation.

This module implements the detonation eligibility gate and the orchestration
logic for MailFort mode.  The actual browser and file runner integrations are
designed as pluggable backends — swap in Playwright, a VM agent, or a cloud
sandbox API without changing the pipeline.

Current status: gate logic and evidence structure are fully implemented.
Browser and file-runner backends are documented stubs ready for integration.
"""

import time
import urllib.parse
from typing import Any, Dict, List, Optional

from ..config import DETONATE_THRESHOLD
from ..models.message import NormalizedMessage
from ..models.findings import StaticAnalysisResult
from ..models.verdict import SandboxEvidence
from ..models.sandbox import SandboxRequest
from ..constants import ARTIFACT_URL, ARTIFACT_ATTACHMENT


# ---------------------------------------------------------------------------
# Detonation gate
# ---------------------------------------------------------------------------

def should_detonate(
    static_result: StaticAnalysisResult,
    detonate_links: bool = True,
    detonate_attachments: bool = True,
) -> bool:
    """Return True if the message should be sent to the sandbox."""
    if static_result.has_critical_rule:
        return True
    if static_result.static_score >= DETONATE_THRESHOLD:
        return True
    if detonate_links and static_result.contains_login_link:
        return True
    if detonate_attachments and static_result.contains_executable_or_macro_attachment:
        return True
    return False


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class SandboxOrchestrator:
    """Coordinate detonation of URLs and attachments for a message."""

    def __init__(
        self,
        detonate_links: bool = True,
        detonate_attachments: bool = True,
        timeout_seconds: int = 120,
    ) -> None:
        self.detonate_links = detonate_links
        self.detonate_attachments = detonate_attachments
        self.timeout_seconds = timeout_seconds

    def run(
        self,
        msg: NormalizedMessage,
        static_result: StaticAnalysisResult,
    ) -> List[SandboxEvidence]:
        """Detonate eligible artifacts and return a list of evidence objects."""
        results: List[SandboxEvidence] = []

        if self.detonate_links:
            for url_dict in static_result.urls:
                url = url_dict.get("original_url", "")
                if not url:
                    continue
                ev = self._detonate_url(url, msg.message_id)
                results.append(ev)

        if self.detonate_attachments:
            for att in msg.attachments:
                data = att.get("data_bytes")
                sha = att.get("sha256") or (
                    __import__("hashlib").sha256(data).hexdigest() if data else "unknown"
                )
                ev = self._detonate_file(sha, att.get("filename", ""), data, msg.message_id)
                results.append(ev)

        return results

    # ------------------------------------------------------------------
    # URL detonation — browser backend stub
    # ------------------------------------------------------------------

    def _detonate_url(self, url: str, message_id: str) -> SandboxEvidence:
        """Detonate a URL in an isolated browser.

        Integration point: replace the body of this method with a real
        Playwright / Selenium / cloud-browser call.  The returned
        SandboxEvidence should be populated from the actual browser session.
        """
        started = time.time()
        evidence = SandboxEvidence(
            artifact_type=ARTIFACT_URL,
            artifact_ref=url,
            status="skipped",  # change to "completed" after real integration
        )

        # --- BEGIN STUB ---
        # Real implementation would:
        # 1. Launch an isolated browser (Playwright headless, Docker container)
        # 2. Navigate to the URL, follow all redirects
        # 3. Capture: final_url, redirect_count, screenshots, network requests
        # 4. Detect: login forms, clipboard access, file download triggers
        # 5. Populate evidence fields and set status = "completed"
        evidence.reasons.append("Sandbox detonation not yet integrated — static analysis only")
        # --- END STUB ---

        return evidence

    # ------------------------------------------------------------------
    # File detonation — file runner stub
    # ------------------------------------------------------------------

    def _detonate_file(
        self,
        sha256: str,
        filename: str,
        data: Optional[bytes],
        message_id: str,
    ) -> SandboxEvidence:
        """Detonate a file in a disposable sandbox environment.

        Integration point: replace the body of this method with a call to
        a VM agent, a cloud sandbox API (e.g. Any.run, Cuckoo, Tria.ge),
        or a local Docker-based executor.
        """
        evidence = SandboxEvidence(
            artifact_type=ARTIFACT_ATTACHMENT,
            artifact_ref=sha256,
            status="skipped",  # change to "completed" after real integration
        )

        # --- BEGIN STUB ---
        # Real implementation would:
        # 1. Submit the file to a sandboxed VM / container
        # 2. Monitor process tree, network activity, file drops, registry changes
        # 3. Detect: persistence, credential harvest, network callbacks
        # 4. Populate evidence fields and set status = "completed"
        evidence.reasons.append(f"File detonation not yet integrated for '{filename}'")
        # --- END STUB ---

        return evidence
