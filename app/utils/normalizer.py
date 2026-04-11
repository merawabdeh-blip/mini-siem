from datetime import datetime
import random

def normalize_log(log_line):

    # -------------------------
    # إذا كان dict (جاي من API)
    # -------------------------
    if isinstance(log_line, dict):
        message = log_line.get("message", "")
        source = log_line.get("source", "api")
        source_ip = log_line.get("source_ip", f"192.168.1.{random.randint(1,255)}")

    # -------------------------
    # إذا كان string (جاي من syslog)
    # -------------------------
    else:
        message = str(log_line)
        source = "syslog"
        source_ip = f"192.168.1.{random.randint(1,255)}"

    # نحول الرسالة لحروف صغيرة لتفادي مشاكل الكتابة
    msg = message.lower()

    # -------------------------
    # Detection Rules
    # -------------------------
    if "failed_login" in msg or "failed password" in msg:
        event_type = "FAILED_LOGIN"
        severity = "high"

    elif "multiple login attempts" in msg or "brute" in msg:
        event_type = "BRUTE_FORCE"
        severity = "high"

    elif "port_scan" in msg or "scan" in msg:
        event_type = "PORT_SCAN"
        severity = "medium"

    elif "login successful" in msg or "accepted password" in msg:
        event_type = "SUCCESS_LOGIN"
        severity = "low"

    elif "attack" in msg:
        event_type = "ATTACK"
        severity = "high"

    else:
        event_type = "UNKNOWN"
        severity = "low"

    # -------------------------
    # Return normalized log
    # -------------------------
    return {
        "source": source,
        "source_ip": source_ip,
        "event_type": event_type,
        "message": message,
        "severity": severity,
        "timestamp": datetime.now().isoformat()
    }
