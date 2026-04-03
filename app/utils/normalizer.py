from datetime import datetime
import random

def normalize_log(log_line):

    # -------------------------
    # إذا كان dict (جاي من API)
    # -------------------------
    if isinstance(log_line, dict):
        message = log_line.get("message", "")

        # 🔥 نفس logic تبع string
        if "Failed password" in message:
            event_type = "FAILED_LOGIN"
            severity = "high"
        elif "Multiple login attempts" in message:
            event_type = "BRUTE_FORCE"
            severity = "high"
        elif "login successful" in message:
            event_type = "SUCCESS_LOGIN"
            severity = "low"
        else:
            event_type = "UNKNOWN"
            severity = "low"

        return {
            "source": log_line.get("source", "api"),
            "source_ip": log_line.get("source_ip", f"192.168.1.{random.randint(1,255)}"),
            "event_type": event_type,
            "message": message,
            "severity": severity,
            "timestamp": datetime.now().isoformat()
        }

    # -------------------------
    # إذا كان string (من file)
    # -------------------------
    log_line = log_line.strip()

    if log_line.startswith("ERROR"):
        severity = "high"
    elif log_line.startswith("WARNING"):
        severity = "medium"
    else:
        severity = "low"

    if "Failed password" in log_line:
        event_type = "FAILED_LOGIN"
    elif "Multiple login attempts" in log_line:
        event_type = "BRUTE_FORCE"
    elif "login successful" in log_line:
        event_type = "SUCCESS_LOGIN"
    else:
        event_type = "UNKNOWN"

    source_ip = f"192.168.1.{random.randint(1,255)}"

    return {
        "source": "auth",
        "source_ip": source_ip,
        "event_type": event_type,
        "message": log_line,
        "severity": severity,
        "timestamp": datetime.now().isoformat()
    }
