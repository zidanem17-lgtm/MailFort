"""Message normalizer — converts provider-specific payloads into NormalizedMessage.

Both the Gmail connector and the IMAP connector feed into this module so
all downstream analyzers operate against a consistent schema regardless of
the originating mail provider.
"""

import base64
import email
import email.header
import email.utils
import hashlib
import re
import time
from email.message import EmailMessage
from typing import Any, Callable, Dict, List, Optional, Tuple

import tldextract

from ..models.message import NormalizedMessage


# ---------------------------------------------------------------------------
# Gmail normalizer
# ---------------------------------------------------------------------------

def normalize_gmail_message(
    raw: Dict[str, Any],
    provider: str = "gmail",
    attachment_fetcher: Optional[Callable[[str, str], Optional[bytes]]] = None,
) -> NormalizedMessage:
    """Convert a full Gmail API message payload into a NormalizedMessage.

    Args:
        raw: The full message dict from messages.get(format='full').
        provider: Provider label to embed in the NormalizedMessage.
        attachment_fetcher: Optional callable ``(message_id, attachment_id) → bytes``
            used to fetch large attachments that are not inlined in the payload.
            Pass ``GmailConnector.fetch_attachment_bytes`` to enable full attachment
            analysis.
    """
    message_id = raw.get("id", "")
    thread_id = raw.get("threadId")
    internal_date = int(raw.get("internalDate", 0))
    labels = raw.get("labelIds", [])

    payload = raw.get("payload", {})
    headers_raw: List[Dict[str, str]] = payload.get("headers", [])
    # Preserve all header values; later headers override earlier for dedup.
    headers: Dict[str, str] = {}
    for h in headers_raw:
        headers[h["name"].lower()] = h["value"]

    from_val = headers.get("from", "")
    sender_display, sender_address = _parse_address(from_val)
    sender_domain = _extract_domain(sender_address)
    reply_to = headers.get("reply-to")
    return_path = headers.get("return-path")
    subject = _decode_header_value(headers.get("subject", "(no subject)"))
    date_str = headers.get("date")

    body_text, body_html, attachments = _extract_gmail_parts(
        payload, message_id, attachment_fetcher=attachment_fetcher
    )

    # Fall back: strip HTML tags for plain-text body if only HTML was found
    if body_text is None and body_html is not None:
        body_text = _strip_html(body_html)

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
    payload: Dict[str, Any],
    message_id: str,
    attachment_fetcher: Optional[Callable[[str, str], Optional[bytes]]] = None,
) -> Tuple[Optional[str], Optional[str], List[Dict[str, Any]]]:
    """Recursively walk a Gmail multipart payload and extract body + attachments.

    Handles:
    - multipart/mixed, multipart/alternative, multipart/related, multipart/signed
    - Inline text/plain and text/html parts at any nesting depth
    - Attachments with inline data (data_b64 present)
    - Large attachments referenced only by attachmentId — fetched via
      *attachment_fetcher* when provided, otherwise queued for deferred fetch
    """
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    attachments: List[Dict[str, Any]] = []

    def walk(part: Dict[str, Any]) -> None:
        nonlocal body_text, body_html
        mime = part.get("mimeType", "").lower()
        sub_parts = part.get("parts", [])

        # Recurse into container types
        if sub_parts:
            for sp in sub_parts:
                walk(sp)
            return

        filename = part.get("filename") or ""
        body = part.get("body", {})
        data_b64: Optional[str] = body.get("data")
        attachment_id: Optional[str] = body.get("attachmentId")
        declared_size: int = body.get("size", 0)

        raw_bytes: Optional[bytes] = None

        if data_b64:
            # Pad to a multiple of 4 before decoding
            padded = data_b64 + "=" * (-len(data_b64) % 4)
            raw_bytes = base64.urlsafe_b64decode(padded)

        # Treat as attachment when a filename is present OR when an
        # attachmentId exists (large attachment stored separately).
        if filename or (attachment_id and mime not in ("text/plain", "text/html")):
            if raw_bytes is None and attachment_id and attachment_fetcher:
                raw_bytes = attachment_fetcher(message_id, attachment_id)

            attachments.append(
                {
                    "filename": filename or "unnamed",
                    "declared_mime": mime,
                    "attachment_id": attachment_id,
                    "message_id": message_id,
                    "data_bytes": raw_bytes,
                    "size_bytes": declared_size or (len(raw_bytes) if raw_bytes else 0),
                    # Flag for deferred fetch if still missing
                    "needs_fetch": (raw_bytes is None and bool(attachment_id)),
                }
            )
            return

        # Body part
        if raw_bytes is None:
            return

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
    # email.Message stores multiple values for repeated headers; take the last.
    for key in set(k.lower() for k in parsed.keys()):
        val = parsed.get(key, "")
        headers[key] = _decode_header_value(str(val))

    from_val = headers.get("from", "")
    sender_display, sender_address = _parse_address(from_val)
    sender_domain = _extract_domain(sender_address)
    reply_to = headers.get("reply-to")
    return_path = headers.get("return-path")
    subject = _decode_header_value(headers.get("subject", "(no subject)"))
    date_str = headers.get("date")
    message_id_hdr = headers.get("message-id", uid).strip(" <>")

    body_text: Optional[str] = None
    body_html: Optional[str] = None
    attachments: List[Dict[str, Any]] = []

    for part in (parsed.walk() if parsed.is_multipart() else [parsed]):
        ct = part.get_content_type().lower()
        cd = str(part.get("Content-Disposition", "")).lower()
        filename = _decode_header_value(part.get_filename() or "")

        # Inline images and related parts without a filename are not attachments
        is_attachment = bool(filename) or "attachment" in cd

        # Inline text parts that are explicitly marked inline and have no
        # filename should still be extracted as body content.
        if not is_attachment and ct == "text/plain" and body_text is None:
            raw = part.get_payload(decode=True)
            if raw:
                charset = part.get_content_charset() or "utf-8"
                body_text = _decode_bytes_with_charset(raw, charset)
            continue

        if not is_attachment and ct == "text/html" and body_html is None:
            raw = part.get_payload(decode=True)
            if raw:
                charset = part.get_content_charset() or "utf-8"
                body_html = _decode_bytes_with_charset(raw, charset)
            continue

        if is_attachment:
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

    # Fallback: if no text/plain found, strip HTML
    if body_text is None and body_html is not None:
        body_text = _strip_html(body_html)

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
    """Extract the registered domain from an email address."""
    if not address or "@" not in address:
        return ""
    _, _, host = address.rpartition("@")
    extracted = tldextract.extract(host)
    if extracted.registered_domain:
        return extracted.registered_domain
    return host.lower()


def _decode_header_value(value: str) -> str:
    """Decode RFC 2047 encoded-words in a header value (e.g. =?utf-8?b?...?=)."""
    if not value:
        return value
    parts = email.header.decode_header(value)
    decoded_parts = []
    for raw, charset in parts:
        if isinstance(raw, bytes):
            decoded_parts.append(_decode_bytes_with_charset(raw, charset or "utf-8"))
        else:
            decoded_parts.append(raw)
    return "".join(decoded_parts)


def _decode_bytes(raw: bytes) -> str:
    """Best-effort decode bytes to a string."""
    for enc in ("utf-8", "latin-1", "cp1252"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, AttributeError):
            continue
    return raw.decode("utf-8", errors="replace")


def _decode_bytes_with_charset(raw: bytes, charset: Optional[str]) -> str:
    """Decode bytes using a declared charset, falling back gracefully."""
    if charset:
        try:
            return raw.decode(charset, errors="replace")
        except (LookupError, TypeError):
            pass
    return _decode_bytes(raw)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s{2,}")


def _strip_html(html: str) -> str:
    """Very lightweight HTML-to-text: strip tags and collapse whitespace."""
    text = _HTML_TAG_RE.sub(" ", html)
    text = _WHITESPACE_RE.sub(" ", text)
    return text.strip()
