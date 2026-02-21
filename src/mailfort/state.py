import os
import sqlite3
import threading

DB_PATH = os.path.join(os.path.expanduser("~"), ".mailfort_state.db")
_lock = threading.Lock()

def init_db(path=None):
    path = path or DB_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
    conn = sqlite3.connect(path, check_same_thread=False)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS scanned (
        message_id TEXT PRIMARY KEY,
        scanned_at REAL
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL,
        action TEXT,
        message_id TEXT,
        sender TEXT,
        confirmed INTEGER
    )
    """)
    conn.commit()
    return conn

def get_conn():
    global _conn
    try:
        _conn
    except NameError:
        _conn = init_db()
    return _conn

def mark_scanned(message_id, ts=None):
    conn = get_conn()
    with _lock:
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO scanned(message_id, scanned_at) VALUES (?, ?)", (message_id, ts or 0))
        conn.commit()

def is_scanned(message_id):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT 1 FROM scanned WHERE message_id = ?", (message_id,))
    return c.fetchone() is not None

def log_audit(ts, action, message_id, sender, confirmed):
    conn = get_conn()
    with _lock:
        c = conn.cursor()
        c.execute("INSERT INTO audit(ts, action, message_id, sender, confirmed) VALUES (?, ?, ?, ?, ?)", (ts, action, message_id, sender, int(bool(confirmed))))
        conn.commit()
