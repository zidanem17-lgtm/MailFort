"""MailFort v2 database initialisation and connection management."""

import os
import sqlite3
import threading

from ..constants import DEFAULT_DB_PATH


_local = threading.local()


SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS messages (
    message_id      TEXT PRIMARY KEY,
    thread_id       TEXT,
    sender          TEXT,
    sender_domain   TEXT,
    subject         TEXT,
    internal_date   INTEGER,
    labels_json     TEXT,
    body_sha256     TEXT,
    html_sha256     TEXT,
    provider        TEXT DEFAULT 'unknown',
    first_seen_ts   REAL,
    last_scanned_ts REAL,
    static_score    INTEGER,
    dynamic_score   INTEGER,
    final_score     INTEGER,
    severity        TEXT,
    confidence      REAL,
    disposition     TEXT
);

CREATE TABLE IF NOT EXISTS urls (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id          TEXT,
    original_url        TEXT,
    normalized_url      TEXT,
    registered_domain   TEXT,
    final_url           TEXT,
    final_domain        TEXT,
    punycode            INTEGER DEFAULT 0,
    lookalike           INTEGER DEFAULT 0,
    brand_impersonation INTEGER DEFAULT 0,
    shortener           INTEGER DEFAULT 0,
    raw_ip              INTEGER DEFAULT 0,
    redirect_count      INTEGER DEFAULT 0,
    evidence_json       TEXT,
    FOREIGN KEY(message_id) REFERENCES messages(message_id)
);

CREATE TABLE IF NOT EXISTS attachments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id      TEXT,
    filename        TEXT,
    sha256          TEXT,
    mime_type       TEXT,
    declared_mime   TEXT,
    extension       TEXT,
    size_bytes      INTEGER,
    entropy         REAL,
    is_archive      INTEGER DEFAULT 0,
    is_macro_doc    INTEGER DEFAULT 0,
    is_pdf          INTEGER DEFAULT 0,
    high_risk       INTEGER DEFAULT 0,
    risk_flags_json TEXT,
    FOREIGN KEY(message_id) REFERENCES messages(message_id)
);

CREATE TABLE IF NOT EXISTS sandbox_runs (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id              TEXT,
    artifact_type           TEXT,
    artifact_ref            TEXT,
    started_ts              REAL,
    ended_ts                REAL,
    status                  TEXT,
    environment             TEXT,
    network_callbacks_json  TEXT,
    process_tree_json       TEXT,
    file_drops_json         TEXT,
    registry_changes_json   TEXT,
    screenshots_json        TEXT,
    evidence_json           TEXT,
    FOREIGN KEY(message_id) REFERENCES messages(message_id)
);

CREATE TABLE IF NOT EXISTS verdicts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id      TEXT,
    static_score    INTEGER,
    dynamic_score   INTEGER,
    final_score     INTEGER,
    severity        TEXT,
    confidence      REAL,
    reasons_json    TEXT,
    policy_action   TEXT,
    created_ts      REAL,
    FOREIGN KEY(message_id) REFERENCES messages(message_id)
);

CREATE TABLE IF NOT EXISTS audit (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL,
    action          TEXT,
    message_id      TEXT,
    sender          TEXT,
    confirmed       INTEGER DEFAULT 0,
    details_json    TEXT
);

CREATE TABLE IF NOT EXISTS allowlists (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    type    TEXT,
    value   TEXT UNIQUE,
    notes   TEXT
);

CREATE TABLE IF NOT EXISTS blocklists (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    type    TEXT,
    value   TEXT UNIQUE,
    notes   TEXT
);

CREATE INDEX IF NOT EXISTS idx_messages_sender_domain ON messages(sender_domain);
CREATE INDEX IF NOT EXISTS idx_messages_severity      ON messages(severity);
CREATE INDEX IF NOT EXISTS idx_urls_message_id        ON urls(message_id);
CREATE INDEX IF NOT EXISTS idx_attachments_message_id ON attachments(message_id);
CREATE INDEX IF NOT EXISTS idx_verdicts_message_id    ON verdicts(message_id);
CREATE INDEX IF NOT EXISTS idx_audit_message_id       ON audit(message_id);
"""


def init_db(path: str = None) -> sqlite3.Connection:
    """Create or open the SQLite database and apply the v2 schema."""
    path = path or DEFAULT_DB_PATH
    dir_path = os.path.dirname(path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)

    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    for statement in SCHEMA_V2.strip().split(";"):
        stmt = statement.strip()
        if stmt:
            conn.execute(stmt)

    conn.execute(
        "INSERT OR IGNORE INTO schema_version(version) VALUES (?)",
        (2,),
    )
    conn.commit()
    return conn


def get_conn(path: str = None) -> sqlite3.Connection:
    """Return a thread-local database connection, initialising if needed."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = init_db(path)
    return _local.conn


def close_conn() -> None:
    """Close the thread-local connection if open."""
    if hasattr(_local, "conn") and _local.conn is not None:
        _local.conn.close()
        _local.conn = None
