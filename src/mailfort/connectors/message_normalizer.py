"""Message normalizer — converts provider-specific payloads into NormalizedMessage.

Both the Gmail connector and the IMAP connector feed into this module so
all downstream analyzers operate against a consistent schema regardless of
the originating mail provider.
"""

import base64
import email
import email.utils
import hashlib
import re
import time
from email.message import EmailMessage
from typing import Any, Dict, List, Optional, Tuple

import tldextract

from ..models.message import NormalizedMessage


# ---------------------------------------------------------------------------
# Gmail normalizer
# ---------------------------------------------------------------------------

def normalize_gmail_message(raw: Dict[str, Any], provider: str = "gmail") -> NormalizedMessage:
    """Convert a full Gmail API message payload into a NormalizedMessage."""
    message_id = raw.get("id", "")
    thread_id = raw.get("threadId")
    internal_date = int(raw.get("internalDate", 0))
    labels = raw.get("labelIds", [])

    # Build flat header dict
    payload = raw.get("payload", {})
    headers_raw: List[Dict[str, str]] = payload.get("headers", [])
    headers: Dict[str, str] = {h["name"].lower(): h["value"] for h in headers_raw}

    from_val = headers.get("from", "")
    sender_display, sender_address = _parse_address(from_val)
    sender_domain = _extract_domain(sender_address)
    reply_to = headers.get("reply-to")
    return_path = headers.get("return-path")
    subject = headers.get("subject", "(no subject)")
    date_str = headers.get("date")

    body_text, body_html, attachments = _extract_gmail_parts(payload, raw.get("id", ""))

    body_sha256 = _sha256(body_text or "")
    html_sha256 = _sha256(body_html or "")

    return NormalizedMessage(
        message_id=message_id,
        thread_id=thread_id,
        provider=provider,
        sender=from_val,
        sender_domain=sender_domain,
        sender_display_name=sender_display,
        sender_address=sender_address,
        reply_to=reply_to,
        return_path=return_path,
        subject=subject,
        date_str=date_str,
        internal_date=internal_date,
        labels=labels,
        headers=headers,
        body_text=body_text,
        body_html=body_html,
        body_sha256=body_sha256,
        html_sha256=html_sha256,
        attachments=attachments,
        raw_payload=raw,
        first_seen_ts=time.time(),
    )


def _extract_gmail_parts(
    payload: Dict[str, Any], message_id: str
) -> Tuple[Optional[str], Optional[str], List[Dict[str, Any]]]:
    """Recursively walk a Gmail message payload and extract body + attachments."""
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    attachments: List[Dict[str, Any]] = []

    def walk(part: Dict[str, Any]) -> None:
        nonlocal body_text, body_html
        mime = part.get("mimeType", "")
        sub_parts = part.get("parts", [])

        if sub_parts:
            for sp in sub_parts:
                walk(sp)
            return

        filename = part.get("filename")
        body = part.get("body", {})
        data_b64 = body.get("data")
        attachment_id = body.get("attachmentId")

        if filename:
            raw_bytes: Optional[bytes] = None
            if data_b64:
                raw_bytes = base64.urlsafe_b64decode(data_b64 + "==")
            attachments.append(
                {
                    "filename": filename,
                    "declared_mime": mime,
                    "attachment_id": attachment_id,
                    "message_id": message_id,
                    "data_bytes": raw_bytes,
                    "size_bytes": body.get("size", len(raw_bytes) if raw_bytes else 0),
                }
            )
            return

        if data_b64:
            raw_bytes = base64.urlsafe_b64decode(data_b64 + "==")
            decoded = _decode_bytes(raw_bytes)
            if mime == "text/plain" and body_text is None:
                body_text = decoded
            elif mime == "text/html" and body_html is None:
                body_html = decoded

    walk(payload)
    return body_text, body_html, attachments


# ---------------------------------------------------------------------------
# IMAP normalizer
# ---------------------------------------------------------------------------

def normalize_imap_message(
    parsed: EmailMessage,
    uid: str,
    provider: str = "imap",
) -> NormalizedMessage:
    """Convert a parsed email.message.EmailMessage into a NormalizedMessage."""
    headers: Dict[str, str] = {}
    for key in parsed.keys():
        headers[key.lower()] = str(parsed[key])

    from_val = headers.get("from", "")
    sender_display, sender_address = _parse_address(from_val)
    sender_domain = _extract_domain(sender_address)
    reply_to = headers.get("reply-to")
    return_path = headers.get("return-path")
    subject = headers.get("subject", "(no subject)")
    date_str = headers.get("date")
    message_id_hdr = headers.get("message-id", uid).strip("<>")

    body_text: Optional[str] = None
    body_html: Optional[str] = None
    attachments: List[Dict[str, Any]] = []

    if parsed.is_multipart():
        for part in parsed.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()

            if filename or "attachment" in cd.lower():
                try:
                    data_bytes = part.get_payload(decode=True)
                except Exception:
                    data_bytes = None
                attachments.append(
                    {
                        "filename": filename or "unnamed",
                        "declared_mime": ct,
                        "message_id": message_id_hdr,
                        "data_bytes": data_bytes,
                        "size_bytes": len(data_bytes) if data_bytes else 0,
                    }
                )
            elif ct == "text/plain" and body_text is None:
                payload = part.get_payload(decode=True)
                if payload:
                    body_text = _decode_bytes(payload)
            elif ct == "text/html" and body_html is None:
                payload = part.get_payload(decode=True)
                if payload:
                    body_html = _decode_bytes(payload)
    else:
        payload = parsed.get_payload(decode=True)
        if payload:
            ct = parsed.get_content_type()
            decoded = _decode_bytes(payload)
            if ct == "text/html":
                body_html = decoded
            else:
                body_text = decoded

    body_sha256 = _sha256(body_text or "")
    html_sha256 = _sha256(body_html or "")

    return NormalizedMessage(
        message_id=message_id_hdr or uid,
        thread_id=None,
        provider=provider,
        sender=from_val,
        sender_domain=sender_domain,
        sender_display_name=sender_display,
        sender_address=sender_address,
        reply_to=reply_to,
        return_path=return_path,
        subject=subject,
        date_str=date_str,
        internal_date=None,
        labels=[],
        headers=headers,
        body_text=body_text,
        body_html=body_html,
        body_sha256=body_sha256,
        html_sha256=html_sha256,
        attachments=attachments,
        raw_payload={"uid": uid},
        first_seen_ts=time.time(),
    )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _parse_address(value: str) -> Tuple[str, str]:
    """Return (display_name, email_address) from a From/Reply-To header value."""
    if not value:
        return ("", "")
    name, addr = email.utils.parseaddr(value)
    return (name.strip(), addr.strip().lower())


def _extract_domain(address: str) -> str:
    """Extract and return just the registered domain from an email address."""
    if not address or "@" not in address:
        return ""
    _, _, host = address.rpartition("@")
    extracted = tldextract.extract(host)
    if extracted.registered_domain:
        return extracted.registered_domain
    return host.lower()


def _decode_bytes(raw: bytes) -> str:
    """Best-effort decode bytes to a string."""
    for enc in ("utf-8", "latin-1", "cp1252"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, AttributeError):
            continue
    return raw.decode("utf-8", errors="replace")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
