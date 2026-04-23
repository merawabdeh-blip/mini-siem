from datetime import datetime
import random
import re


def extract_ip(text: str) -> str:
    if not text:
        return f"192.168.1.{random.randint(2, 254)}"

    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    if match:
        return match.group(0)

    return f"192.168.1.{random.randint(2, 254)}"


def detect_source(log_line, message: str) -> str:
    if isinstance(log_line, dict):
        source = str(log_line.get("source", "")).strip().lower()
        if source:
            return source

        if log_line.get("agent") or log_line.get("decoder"):
            return "wazuh"

    msg = (message or "").lower()

    if "sshd" in msg or "authentication" in msg or "invalid password" in msg:
        return "auth"
    if "nginx" in msg or "apache" in msg or "http" in msg or "web" in msg:
        return "web"
    if "port scan" in msg or "port_scan" in msg or "portscan" in msg or "nmap" in msg or "network" in msg:
        return "network"
    if "kernel" in msg or "systemd" in msg or "sudo" in msg:
        return "system"
    if "wazuh" in msg:
        return "wazuh"
    if "dataset" in msg:
        return "dataset"

    return "api" if isinstance(log_line, dict) else "syslog"


def detect_event_type(message: str, source: str) -> str:
    msg = (message or "").lower().strip()

    if not msg:
        return "EMPTY_LOG"

    if msg.isdigit():
        return "NOISE"

    # Dataset-aware mapping
    if "benign" in msg:
        return "NORMAL"

    if "dos" in msg or "ddos" in msg:
        return "DOS"

    if "portscan" in msg or "port scan" in msg or "port_scan" in msg:
        return "PORT_SCAN"

    if "bot" in msg:
        return "BOTNET"

    if "brute" in msg or "brute_force" in msg:
        return "BRUTE_FORCE"

    if "infiltration" in msg:
        return "INFILTRATION"

    if "web attack" in msg:
        return "WEB_ATTACK"

    if source == "system":
        if "sudo session opened" in msg or "session opened for root" in msg:
            return "PRIVILEGE_ESCALATION"
        if "kernel" in msg or "systemd" in msg or "sudo" in msg:
            return "SYSTEM_ACTIVITY"

    if (
        "failed password" in msg
        or "authentication failure" in msg
        or "invalid user" in msg
        or "invalid password" in msg
        or "login failed" in msg
        or "failed login" in msg
        or "failed_login" in msg
    ):
        return "FAILED_LOGIN"

    if (
        "multiple login attempts" in msg
        or "brute force" in msg
        or "too many login attempts" in msg
        or "brute_force" in msg
    ):
        return "BRUTE_FORCE"

    if (
        "port scan" in msg
        or "port_scan" in msg
        or "portscan" in msg
        or "nmap" in msg
        or "scan detected" in msg
    ):
        return "PORT_SCAN"

    if (
        "login successful" in msg
        or "accepted password" in msg
        or "session opened" in msg
        or "user logged in" in msg
        or "logged in" in msg
        or "login success" in msg
    ):
        return "SUCCESS_LOGIN"

    if "malware" in msg or "virus" in msg or "trojan" in msg or "ransomware" in msg:
        return "MALWARE"

    if "attack" in msg or "intrusion" in msg or "exploit" in msg:
        return "ATTACK"

    if source == "network" and "scan" in msg:
        return "PORT_SCAN"

    if source == "auth" and ("login" in msg or "password" in msg):
        return "FAILED_LOGIN"

    return "UNKNOWN"


def detect_severity(event_type: str, source: str, message: str) -> str:
    msg = (message or "").lower()

    if event_type in [
        "BRUTE_FORCE",
        "PORT_SCAN",
        "MALWARE",
        "ATTACK",
        "PRIVILEGE_ESCALATION",
        "DOS",
        "BOTNET",
        "INFILTRATION",
        "WEB_ATTACK",
    ]:
        return "high"

    if event_type == "FAILED_LOGIN":
        return "medium"

    if event_type in ["SUCCESS_LOGIN", "SYSTEM_ACTIVITY", "NORMAL"]:
        return "low"

    if event_type in ["EMPTY_LOG", "NOISE", "UNKNOWN"]:
        return "low"

    if "critical" in msg:
        return "critical"
    if "high" in msg:
        return "high"
    if "medium" in msg:
        return "medium"
    if "low" in msg:
        return "low"

    return "low"


def normalize_log(log_line):
    timestamp = datetime.now().isoformat()

    if isinstance(log_line, dict):
        message = str(
            log_line.get("message")
            or log_line.get("log")
            or log_line.get("full_log")
            or log_line.get("data", {}).get("message", "")
        ).strip()

        source = detect_source(log_line, message)

        source_ip = str(
            log_line.get("source_ip")
            or log_line.get("srcip")
            or log_line.get("agent", {}).get("ip")
            or extract_ip(message)
        ).strip()

        event_type = detect_event_type(message, source)

        severity = str(log_line.get("severity") or "").strip().lower()
        if not severity:
            severity = detect_severity(event_type, source, message)

        timestamp = str(log_line.get("timestamp") or log_line.get("@timestamp") or timestamp)

        return {
            "source": source,
            "source_ip": source_ip,
            "event_type": event_type,
            "message": message,
            "severity": severity,
            "timestamp": timestamp
        }

    message = str(log_line).strip()
    source = detect_source(log_line, message)
    event_type = detect_event_type(message, source)
    severity = detect_severity(event_type, source, message)

    return {
        "source": source,
        "source_ip": extract_ip(message),
        "event_type": event_type,
        "message": message,
        "severity": severity,
        "timestamp": timestamp
    }
