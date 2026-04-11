"""Schema migration helpers for MailFort persistence layer."""

import sqlite3
from typing import Optional


def get_schema_version(conn: sqlite3.Connection) -> int:
    try:
        row = conn.execute(
            "SELECT MAX(version) FROM schema_version"
        ).fetchone()
        return row[0] if row and row[0] is not None else 0
    except sqlite3.OperationalError:
        return 0


def migrate_v1_to_v2(conn: sqlite3.Connection) -> None:
    """Add columns introduced in the v2 schema to an existing v1 database."""
    cursor = conn.cursor()

    def column_exists(table: str, column: str) -> bool:
        rows = cursor.execute(f"PRAGMA table_info({table})").fetchall()
        return any(r[1] == column for r in rows)

    def add_column_if_missing(table: str, column: str, col_def: str) -> None:
        if not column_exists(table, column):
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")

    # messages table additions
    add_column_if_missing("messages", "provider", "TEXT DEFAULT 'unknown'")
    add_column_if_missing("messages", "dynamic_score", "INTEGER")
    add_column_if_missing("messages", "confidence", "REAL")
    add_column_if_missing("messages", "disposition", "TEXT")

    # audit table addition
    add_column_if_missing("audit", "details_json", "TEXT")

    # New tables from v2
    cursor.executescript("""
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
    """)

    cursor.execute(
        "INSERT OR REPLACE INTO schema_version(version) VALUES (?)", (2,)
    )
    conn.commit()


def run_migrations(conn: sqlite3.Connection) -> None:
    """Apply any pending migrations."""
    version = get_schema_version(conn)
    if version < 2:
        migrate_v1_to_v2(conn)
