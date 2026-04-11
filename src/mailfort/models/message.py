"""Normalized message model — provider-agnostic."""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


@dataclass
class NormalizedMessage:
    """A fully normalized email message extracted from any mail provider.

    The connector layer (Gmail, IMAP, Graph) is responsible for populating
    this dataclass so that all downstream analyzers and the verdict engine
    operate against a consistent schema.
    """

    # Core identity
    message_id: str
    thread_id: Optional[str]
    provider: str  # gmail | imap | graph

    # Sender envelope
    sender: str                   # raw From header value
    sender_domain: str            # registered domain extracted from address
    sender_display_name: str      # display portion of From header
    sender_address: str           # bare email address from From header

    # Routing headers
    reply_to: Optional[str]
    return_path: Optional[str]

    # Subject and date
    subject: str
    date_str: Optional[str]
    internal_date: Optional[int]  # epoch milliseconds (Gmail) or None

    # Gmail-specific metadata
    labels: List[str] = field(default_factory=list)

    # All raw headers as a flat dict (lowercase keys)
    headers: Dict[str, str] = field(default_factory=dict)

    # Body content
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    body_sha256: Optional[str] = None
    html_sha256: Optional[str] = None

    # Attachments — each entry is a dict with at minimum:
    #   filename, size_bytes, mime_type (declared), data_bytes (raw bytes or None)
    attachments: List[Dict[str, Any]] = field(default_factory=list)

    # Raw provider payload for debugging
    raw_payload: Optional[Dict[str, Any]] = None

    # Timestamps set by the persistence layer
    first_seen_ts: Optional[float] = None
    last_scanned_ts: Optional[float] = None

    def header(self, name: str, default: str = "") -> str:
        """Return a header value by case-insensitive name."""
        return self.headers.get(name.lower(), default)
