import sqlite3
from datetime import datetime

DATABASE = "siem.db"


def get_db():
    conn = sqlite3.connect(DATABASE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # ==========================
    # logs table
    # ==========================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            source_ip TEXT,
            event_type TEXT,
            message TEXT,
            severity TEXT,
            timestamp TEXT
        )
    """)

    # ==========================
    # alerts table
    # ==========================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            source_ip TEXT,
            description TEXT,
            severity TEXT,
            timestamp TEXT
        )
    """)

    # ==========================
    # users table
    # ==========================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password_hash TEXT,
            role TEXT DEFAULT 'viewer',
            created_at TEXT
        )
    """)

    conn.commit()
    conn.close()


def insert_log(conn, source, source_ip, event_type, message, severity, timestamp):
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO logs (source, source_ip, event_type, message, severity, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (source, source_ip, event_type, message, severity, timestamp))
    conn.commit()


def insert_alert(conn, alert_type, source_ip, description, severity, timestamp):
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alerts (type, source_ip, description, severity, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (alert_type, source_ip, description, severity, timestamp))
    conn.commit()


def insert_user(conn, username, email, password_hash, role):
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (username, email, password_hash, role, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (username, email, password_hash, role, datetime.utcnow().isoformat()))
    conn.commit()


def get_user_by_username(conn, username):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()
