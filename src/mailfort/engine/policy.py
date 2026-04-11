"""Policy engine — translates verdicts into concrete Gmail/IMAP actions."""

import time
from typing import Optional

from ..constants import (
    ACTION_ALLOW, ACTION_WARN, ACTION_QUARANTINE,
    ACTION_BLOCK, ACTION_ESCALATE,
    LABEL_QUARANTINE, LABEL_REVIEW,
)
from ..config import DEFAULT_POLICY
from ..models.verdict import Verdict
from ..models.policy import PolicyResult
from ..persistence.repositories import log_audit


class PolicyEngine:
    """Apply a verdict to a mail provider and record the audit trail."""

    def __init__(
        self,
        connector=None,       # GmailConnector or ImapConnector
        dry_run: bool = True,
        custom_policy: Optional[dict] = None,
    ) -> None:
        self.connector = connector
        self.dry_run = dry_run
        self.policy = custom_policy or DEFAULT_POLICY

    def apply(self, verdict: Verdict, sender: str = "") -> PolicyResult:
        """Decide on and execute a policy action for the given verdict."""
        action = self._decide(verdict)
        policy_result = PolicyResult(
            action=action,
            message_id=verdict.message_id,
            severity=verdict.severity,
            reasons=verdict.reasons[:10],
            dry_run=self.dry_run,
            applied_ts=time.time(),
        )

        if action == ACTION_QUARANTINE:
            self._quarantine(verdict.message_id, policy_result)
        elif action == ACTION_WARN:
            policy_result.notified = False  # notification handled externally
        elif action in (ACTION_BLOCK, ACTION_ESCALATE):
            self._quarantine(verdict.message_id, policy_result)

        log_audit(
            action=action,
            message_id=verdict.message_id,
            sender=sender,
            confirmed=True,
            details={
                "severity": verdict.severity,
                "final_score": verdict.final_score,
                "dry_run": self.dry_run,
            },
        )

        return policy_result

    # ------------------------------------------------------------------

    def _decide(self, verdict: Verdict) -> str:
        """Look up the default action for this severity, respecting overrides."""
        return self.policy.get(verdict.severity, ACTION_ALLOW)

    def _quarantine(self, message_id: str, policy_result: PolicyResult) -> None:
        """Apply quarantine label or IMAP move, depending on the connector type."""
        from ..connectors.gmail import GmailConnector
        from ..connectors.imap import ImapConnector

        policy_result.label_applied = LABEL_QUARANTINE

        if self.dry_run:
            policy_result.quarantined = True
            return

        if self.connector is None:
            policy_result.quarantined = True
            return

        try:
            if isinstance(self.connector, GmailConnector):
                label_id = self.connector.create_label_if_missing(LABEL_QUARANTINE)
                self.connector.quarantine_message(message_id, label_id)
                policy_result.quarantined = True

            elif isinstance(self.connector, ImapConnector):
                uid = message_id  # IMAP uses UID as the identifier
                policy_result.quarantined = self.connector.quarantine_message(uid)

        except Exception as e:
            policy_result.reasons.append(f"Quarantine action failed: {e}")

    def release(self, message_id: str, sender: str = "") -> PolicyResult:
        """Release a quarantined message back to INBOX."""
        from ..connectors.gmail import GmailConnector
        from ..connectors.imap import ImapConnector

        policy_result = PolicyResult(
            action="release",
            message_id=message_id,
            severity="",
            dry_run=self.dry_run,
            applied_ts=time.time(),
        )

        if self.dry_run:
            policy_result.label_applied = LABEL_REVIEW
            return policy_result

        try:
            if isinstance(self.connector, GmailConnector):
                quarantine_id = self.connector.label_name_to_id(LABEL_QUARANTINE)
                cleared_id = self.connector.create_label_if_missing(LABEL_REVIEW)
                if quarantine_id:
                    self.connector.release_message(message_id, quarantine_id, cleared_id)
                policy_result.quarantined = False

            elif isinstance(self.connector, ImapConnector):
                policy_result.quarantined = not self.connector.release_message(message_id)

        except Exception as e:
            policy_result.reasons.append(f"Release action failed: {e}")

        log_audit(
            action="release",
            message_id=message_id,
            sender=sender,
            confirmed=True,
            details={"dry_run": self.dry_run},
        )
        return policy_result
