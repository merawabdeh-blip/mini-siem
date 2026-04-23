from app.database import get_db, insert_audit_log


def log_audit_event(username: str, action: str, endpoint: str):
    db_gen = get_db()
    conn = next(db_gen)
    insert_audit_log(conn, username, action, endpoint)
    conn.close()
