import sqlite3

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
    # alerts table (🔥 UPDATED)
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

    conn.commit()
    conn.close()


# ==========================
# Insert Alert (🔥 UPDATED)
# ==========================
def insert_alert(conn, alert_type, source_ip, description, severity, timestamp):
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alerts (type, source_ip, description, severity, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (alert_type, source_ip, description, severity, timestamp))
    conn.commit()
