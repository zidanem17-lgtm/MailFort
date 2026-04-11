"""IMAP connector for enterprise custom-domain mailboxes.

Supports any business domain that exposes IMAP (Office 365, Google Workspace,
Postfix, Exchange, Zimbra, etc.).  MailFort's enterprise-grade email domain
analysis is delivered through this connector — giving security teams coverage
beyond personal Gmail accounts and into organisational mail environments.

Usage example:

    from mailfort.connectors.imap import ImapConnector

    connector = ImapConnector(
        host="mail.company.com",
        port=993,
        username="security@company.com",
        password="app-password",
        use_ssl=True,
        mailbox="INBOX",
    )
    with connector:
        for msg in connector.list_messages(max_messages=50):
            raw = connector.fetch_message(msg["uid"])
            ...
"""

import email
import imaplib
import re
import time
from email import policy as email_policy
from email.headerregistry import Address
from typing import Iterator, Optional, List, Dict, Any


class ImapConnector:
    """IMAP-based mail connector for enterprise / custom-domain deployments."""

    def __init__(
        self,
        host: str,
        port: int = 993,
        username: str = "",
        password: str = "",
        use_ssl: bool = True,
        mailbox: str = "INBOX",
        timeout: int = 30,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.mailbox = mailbox
        self.timeout = timeout
        self._conn: Optional[imaplib.IMAP4_SSL | imaplib.IMAP4] = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> None:
        if self.use_ssl:
            self._conn = imaplib.IMAP4_SSL(self.host, self.port)
        else:
            self._conn = imaplib.IMAP4(self.host, self.port)
        self._conn.login(self.username, self.password)
        self._select_mailbox(self.mailbox)

    def disconnect(self) -> None:
        if self._conn:
            try:
                self._conn.logout()
            except Exception:
                pass
            self._conn = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()

    def _ensure_connected(self) -> None:
        if self._conn is None:
            self.connect()

    def _select_mailbox(self, mailbox: str) -> None:
        status, data = self._conn.select(mailbox)
        if status != "OK":
            raise RuntimeError(
                f"Could not select mailbox '{mailbox}': {data}"
            )

    # ------------------------------------------------------------------
    # Message listing
    # ------------------------------------------------------------------

    def list_mailboxes(self) -> List[str]:
        """Return a list of available mailbox folder names."""
        self._ensure_connected()
        status, data = self._conn.list()
        if status != "OK":
            return []
        results = []
        for item in data:
            if isinstance(item, bytes):
                decoded = item.decode(errors="replace")
                parts = decoded.rsplit('"."', 1)
                if len(parts) == 2:
                    results.append(parts[1].strip().strip('"'))
                else:
                    results.append(decoded)
        return results

    def list_messages(
        self,
        search_criteria: str = "ALL",
        max_messages: int = 100,
    ) -> Iterator[Dict[str, Any]]:
        """Yield lightweight message stubs (UID + header summary).

        Args:
            search_criteria: IMAP SEARCH string, e.g. "UNSEEN", "ALL",
                "SINCE 01-Jan-2025", "FROM attacker@evil.com".
            max_messages: Cap on the number of messages yielded.
        """
        self._ensure_connected()
        status, data = self._conn.uid("SEARCH", None, search_criteria)
        if status != "OK" or not data[0]:
            return

        uids = data[0].split()
        # Newest first
        uids = list(reversed(uids))
        if max_messages:
            uids = uids[:max_messages]

        for uid_bytes in uids:
            uid = uid_bytes.decode()
            try:
                stub = self._fetch_envelope(uid)
                if stub:
                    yield stub
            except Exception:
                continue

    def _fetch_envelope(self, uid: str) -> Optional[Dict[str, Any]]:
        """Fetch ENVELOPE data for a lightweight message stub."""
        status, data = self._conn.uid(
            "FETCH", uid, "(ENVELOPE RFC822.SIZE)"
        )
        if status != "OK" or not data or data[0] is None:
            return None

        # ENVELOPE fields: date, subject, from, sender, reply-to,
        # to, cc, bcc, in-reply-to, message-id
        raw_response = data[0]
        if isinstance(raw_response, tuple):
            response_str = raw_response[1].decode(errors="replace") if isinstance(raw_response[1], bytes) else str(raw_response[1])
        else:
            response_str = raw_response.decode(errors="replace") if isinstance(raw_response, bytes) else str(raw_response)

        return {
            "uid": uid,
            "raw_envelope": response_str,
        }

    # ------------------------------------------------------------------
    # Full message fetch
    # ------------------------------------------------------------------

    def fetch_message(self, uid: str) -> Optional[email.message.EmailMessage]:
        """Fetch and parse the full RFC822 message for the given UID."""
        self._ensure_connected()
        status, data = self._conn.uid("FETCH", uid, "(RFC822)")
        if status != "OK" or not data or data[0] is None:
            return None
        raw_bytes = data[0][1] if isinstance(data[0], tuple) else data[0]
        if not isinstance(raw_bytes, bytes):
            return None
        return email.message_from_bytes(raw_bytes, policy=email_policy.default)

    def fetch_message_bytes(self, uid: str) -> Optional[bytes]:
        """Return the raw RFC822 bytes for a message UID."""
        self._ensure_connected()
        status, data = self._conn.uid("FETCH", uid, "(RFC822)")
        if status != "OK" or not data or data[0] is None:
            return None
        return data[0][1] if isinstance(data[0], tuple) else data[0]

    # ------------------------------------------------------------------
    # Label / folder operations (IMAP move = COPY + DELETE)
    # ------------------------------------------------------------------

    def move_to_folder(self, uid: str, destination: str) -> bool:
        """Move a message to a different IMAP folder."""
        self._ensure_connected()
        # Ensure destination exists
        self._conn.create(destination)
        status, _ = self._conn.uid("COPY", uid, destination)
        if status != "OK":
            return False
        self._conn.uid("STORE", uid, "+FLAGS", "\\Deleted")
        self._conn.expunge()
        return True

    def mark_as_read(self, uid: str) -> bool:
        self._ensure_connected()
        status, _ = self._conn.uid("STORE", uid, "+FLAGS", "\\Seen")
        return status == "OK"

    def mark_as_unread(self, uid: str) -> bool:
        self._ensure_connected()
        status, _ = self._conn.uid("STORE", uid, "-FLAGS", "\\Seen")
        return status == "OK"

    def flag_message(self, uid: str) -> bool:
        self._ensure_connected()
        status, _ = self._conn.uid("STORE", uid, "+FLAGS", "\\Flagged")
        return status == "OK"

    # ------------------------------------------------------------------
    # Quarantine helpers
    # ------------------------------------------------------------------

    QUARANTINE_FOLDER = "MAILFORT/QUARANTINE"
    REVIEW_FOLDER = "MAILFORT/REVIEW"

    def quarantine_message(self, uid: str) -> bool:
        """Move message to the MAILFORT/QUARANTINE folder."""
        return self.move_to_folder(uid, self.QUARANTINE_FOLDER)

    def release_message(self, uid: str, restore_folder: str = "INBOX") -> bool:
        """Move a quarantined message back to INBOX (or specified folder)."""
        # Re-select quarantine folder first
        self._conn.select(self.QUARANTINE_FOLDER)
        result = self.move_to_folder(uid, restore_folder)
        # Re-select original mailbox
        self._select_mailbox(self.mailbox)
        return result

    # ------------------------------------------------------------------
    # Stats / info
    # ------------------------------------------------------------------

    def get_mailbox_status(self) -> Dict[str, int]:
        """Return message counts for the current mailbox."""
        self._ensure_connected()
        status, data = self._conn.status(
            self.mailbox, "(MESSAGES UNSEEN RECENT)"
        )
        if status != "OK" or not data:
            return {}
        text = data[0].decode(errors="replace")
        counts: Dict[str, int] = {}
        for key in ("MESSAGES", "UNSEEN", "RECENT"):
            m = re.search(rf"{key} (\d+)", text)
            if m:
                counts[key.lower()] = int(m.group(1))
        return counts
