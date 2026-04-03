from datetime import datetime, timedelta
from app.database import get_db

def detect_bruteforce(source_ip):
    db = next(get_db())
    cursor = db.cursor()

    # ⏱️ آخر دقيقة
    one_minute_ago = datetime.utcnow() - timedelta(minutes=1)

    # 🔥 نحسب فقط خلال آخر دقيقة
    cursor.execute("""
    SELECT COUNT(*) FROM logs
    WHERE source_ip=? 
    AND event_type='login_failure'
    AND timestamp >= ?
    """, (source_ip, one_minute_ago))

    count = cursor.fetchone()[0]

    print("BRUTE DEBUG =", count)

    # 🚨 إذا أكثر من 5 خلال دقيقة
    if count >= 5:

        cursor.execute("""
        SELECT COUNT(*) FROM alerts
        WHERE source_ip=? 
        AND type='BRUTE_FORCE'
        """, (source_ip,))

        existing = cursor.fetchone()[0]

        if existing == 0:
            cursor.execute("""
            INSERT INTO alerts (type, source_ip, description)
            VALUES (?, ?, ?)
            """, (
                "BRUTE_FORCE",
                source_ip,
                f"{count} failed login attempts in 1 minute"
            ))

            db.commit()


def detect_portscan(source_ip):
    db = next(get_db())
    cursor = db.cursor()

    # آخر دقيقة
    one_minute_ago = datetime.utcnow() - timedelta(minutes=1)

    cursor.execute("""
        SELECT DISTINCT message FROM logs
        WHERE source_ip = ?
        AND event_type = 'port_scan'
        AND timestamp >= ?
    """, (source_ip, one_minute_ago.isoformat()))

    ports = cursor.fetchall()

    print(f"PORTSCAN DEBUG = {len(ports)}")

    if len(ports) >= 5:
        cursor.execute("""
            INSERT INTO alerts (type, source_ip, description)
            VALUES (?, ?, ?)
        """, (
            "PORT_SCAN",
            source_ip,
            f"{len(ports)} ports scanned in 1 minute"
        ))
        db.commit()
