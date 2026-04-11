"""Repository pattern for database access in MailFort v2."""

import json
import time
import sqlite3
import threading
from typing import Optional, List, Dict, Any

from .db import get_conn

_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------

def save_message(
    msg_dict: Dict[str, Any],
    static_score: int = 0,
    dynamic_score: int = 0,
    final_score: int = 0,
    severity: str = "benign",
    confidence: float = 0.0,
    disposition: str = "allow",
    conn: Optional[sqlite3.Connection] = None,
) -> None:
    conn = conn or get_conn()
    now = time.time()
    with _lock:
        conn.execute(
            """
            INSERT INTO messages (
                message_id, thread_id, sender, sender_domain, subject,
                internal_date, labels_json, body_sha256, html_sha256, provider,
                first_seen_ts, last_scanned_ts,
                static_score, dynamic_score, final_score, severity, confidence, disposition
            ) VALUES (
                :message_id, :thread_id, :sender, :sender_domain, :subject,
                :internal_date, :labels_json, :body_sha256, :html_sha256, :provider,
                :first_seen_ts, :last_scanned_ts,
                :static_score, :dynamic_score, :final_score, :severity, :confidence, :disposition
            )
            ON CONFLICT(message_id) DO UPDATE SET
                last_scanned_ts = excluded.last_scanned_ts,
                static_score    = excluded.static_score,
                dynamic_score   = excluded.dynamic_score,
                final_score     = excluded.final_score,
                severity        = excluded.severity,
                confidence      = excluded.confidence,
                disposition     = excluded.disposition
            """,
            {
                "message_id": msg_dict.get("message_id"),
                "thread_id": msg_dict.get("thread_id"),
                "sender": msg_dict.get("sender"),
                "sender_domain": msg_dict.get("sender_domain"),
                "subject": msg_dict.get("subject"),
                "internal_date": msg_dict.get("internal_date"),
                "labels_json": json.dumps(msg_dict.get("labels", [])),
                "body_sha256": msg_dict.get("body_sha256"),
                "html_sha256": msg_dict.get("html_sha256"),
                "provider": msg_dict.get("provider", "unknown"),
                "first_seen_ts": msg_dict.get("first_seen_ts") or now,
                "last_scanned_ts": now,
                "static_score": static_score,
                "dynamic_score": dynamic_score,
                "final_score": final_score,
                "severity": severity,
                "confidence": confidence,
                "disposition": disposition,
            },
        )
        conn.commit()


def was_recently_scanned(
    message_id: str,
    max_age_seconds: float = 3600,
    conn: Optional[sqlite3.Connection] = None,
) -> bool:
    conn = conn or get_conn()
    row = conn.execute(
        "SELECT last_scanned_ts FROM messages WHERE message_id = ?",
        (message_id,),
    ).fetchone()
    if row is None:
        return False
    return (time.time() - (row[0] or 0)) < max_age_seconds


def get_message(
    message_id: str,
    conn: Optional[sqlite3.Connection] = None,
) -> Optional[Dict[str, Any]]:
    conn = conn or get_conn()
    row = conn.execute(
        "SELECT * FROM messages WHERE message_id = ?", (message_id,)
    ).fetchone()
    return dict(row) if row else None


def list_messages(
    severity: Optional[str] = None,
    limit: int = 200,
    conn: Optional[sqlite3.Connection] = None,
) -> List[Dict[str, Any]]:
    conn = conn or get_conn()
    if severity:
        rows = conn.execute(
            "SELECT * FROM messages WHERE severity = ? ORDER BY last_scanned_ts DESC LIMIT ?",
            (severity, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM messages ORDER BY last_scanned_ts DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# URLs
# ---------------------------------------------------------------------------

def save_url(url_dict: Dict[str, Any], conn: Optional[sqlite3.Connection] = None) -> None:
    conn = conn or get_conn()
    with _lock:
        conn.execute(
            """
            INSERT INTO urls (
                message_id, original_url, normalized_url, registered_domain,
                final_url, final_domain, punycode, lookalike, brand_impersonation,
                shortener, raw_ip, redirect_count, evidence_json
            ) VALUES (
                :message_id, :original_url, :normalized_url, :registered_domain,
                :final_url, :final_domain, :punycode, :lookalike, :brand_impersonation,
                :shortener, :raw_ip, :redirect_count, :evidence_json
            )
            """,
            {
                "message_id": url_dict.get("message_id"),
                "original_url": url_dict.get("original_url"),
                "normalized_url": url_dict.get("normalized_url"),
                "registered_domain": url_dict.get("registered_domain"),
                "final_url": url_dict.get("final_url"),
                "final_domain": url_dict.get("final_domain"),
                "punycode": int(url_dict.get("is_punycode", False)),
                "lookalike": int(url_dict.get("is_lookalike", False)),
                "brand_impersonation": int(url_dict.get("is_brand_impersonation", False)),
                "shortener": int(url_dict.get("is_shortener", False)),
                "raw_ip": int(url_dict.get("is_raw_ip", False)),
                "redirect_count": url_dict.get("redirect_count", 0),
                "evidence_json": json.dumps(url_dict.get("evidence", {})),
            },
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Attachments
# ---------------------------------------------------------------------------

def save_attachment(att_dict: Dict[str, Any], conn: Optional[sqlite3.Connection] = None) -> None:
    conn = conn or get_conn()
    with _lock:
        conn.execute(
            """
            INSERT INTO attachments (
                message_id, filename, sha256, mime_type, declared_mime, extension,
                size_bytes, entropy, is_archive, is_macro_doc, is_pdf, high_risk, risk_flags_json
            ) VALUES (
                :message_id, :filename, :sha256, :mime_type, :declared_mime, :extension,
                :size_bytes, :entropy, :is_archive, :is_macro_doc, :is_pdf, :high_risk, :risk_flags_json
            )
            """,
            {
                "message_id": att_dict.get("message_id"),
                "filename": att_dict.get("filename"),
                "sha256": att_dict.get("sha256"),
                "mime_type": att_dict.get("mime_type"),
                "declared_mime": att_dict.get("declared_mime"),
                "extension": att_dict.get("extension"),
                "size_bytes": att_dict.get("size_bytes", 0),
                "entropy": att_dict.get("entropy", 0.0),
                "is_archive": int(att_dict.get("is_archive", False)),
                "is_macro_doc": int(att_dict.get("is_macro_doc", False)),
                "is_pdf": int(att_dict.get("is_pdf", False)),
                "high_risk": int(att_dict.get("high_risk", False)),
                "risk_flags_json": json.dumps(att_dict.get("risk_flags", [])),
            },
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------

def save_verdict(verdict_dict: Dict[str, Any], conn: Optional[sqlite3.Connection] = None) -> None:
    conn = conn or get_conn()
    with _lock:
        conn.execute(
            """
            INSERT INTO verdicts (
                message_id, static_score, dynamic_score, final_score,
                severity, confidence, reasons_json, policy_action, created_ts
            ) VALUES (
                :message_id, :static_score, :dynamic_score, :final_score,
                :severity, :confidence, :reasons_json, :policy_action, :created_ts
            )
            """,
            {
                "message_id": verdict_dict.get("message_id"),
                "static_score": verdict_dict.get("static_score", 0),
                "dynamic_score": verdict_dict.get("dynamic_score", 0),
                "final_score": verdict_dict.get("final_score", 0),
                "severity": verdict_dict.get("severity"),
                "confidence": verdict_dict.get("confidence", 0.0),
                "reasons_json": json.dumps(verdict_dict.get("reasons", [])),
                "policy_action": verdict_dict.get("recommended_action"),
                "created_ts": verdict_dict.get("created_ts") or time.time(),
            },
        )
        conn.commit()


def get_latest_verdict(
    message_id: str,
    conn: Optional[sqlite3.Connection] = None,
) -> Optional[Dict[str, Any]]:
    conn = conn or get_conn()
    row = conn.execute(
        "SELECT * FROM verdicts WHERE message_id = ? ORDER BY created_ts DESC LIMIT 1",
        (message_id,),
    ).fetchone()
    if row is None:
        return None
    d = dict(row)
    d["reasons"] = json.loads(d.get("reasons_json") or "[]")
    return d


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def log_audit(
    action: str,
    message_id: str,
    sender: str,
    confirmed: bool,
    details: Optional[Dict[str, Any]] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> None:
    conn = conn or get_conn()
    with _lock:
        conn.execute(
            """
            INSERT INTO audit (ts, action, message_id, sender, confirmed, details_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                time.time(),
                action,
                message_id,
                sender,
                int(confirmed),
                json.dumps(details or {}),
            ),
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Allowlists / Blocklists
# ---------------------------------------------------------------------------

def add_to_allowlist(
    entry_type: str,
    value: str,
    notes: str = "",
    conn: Optional[sqlite3.Connection] = None,
) -> None:
    conn = conn or get_conn()
    with _lock:
        conn.execute(
            "INSERT OR IGNORE INTO allowlists (type, value, notes) VALUES (?, ?, ?)",
            (entry_type, value, notes),
        )
        conn.commit()


def add_to_blocklist(
    entry_type: str,
    value: str,
    notes: str = "",
    conn: Optional[sqlite3.Connection] = None,
) -> None:
    conn = conn or get_conn()
    with _lock:
        conn.execute(
            "INSERT OR IGNORE INTO blocklists (type, value, notes) VALUES (?, ?, ?)",
            (entry_type, value, notes),
        )
        conn.commit()


def is_allowlisted(
    entry_type: str,
    value: str,
    conn: Optional[sqlite3.Connection] = None,
) -> bool:
    conn = conn or get_conn()
    row = conn.execute(
        "SELECT 1 FROM allowlists WHERE type = ? AND value = ?",
        (entry_type, value),
    ).fetchone()
    return row is not None


def is_blocklisted(
    entry_type: str,
    value: str,
    conn: Optional[sqlite3.Connection] = None,
) -> bool:
    conn = conn or get_conn()
    row = conn.execute(
        "SELECT 1 FROM blocklists WHERE type = ? AND value = ?",
        (entry_type, value),
    ).fetchone()
    return row is not None
