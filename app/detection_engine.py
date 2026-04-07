from collections import defaultdict
from app.ai_analyzer import predict_log


def run_detection(logs):
    alerts = []

    failed_login_counter = defaultdict(int)
    port_scan_counter = defaultdict(set)

    # =========================
    # 1. Rule-Based Detection
    # =========================
    for log in logs:
        ip = log.get("source_ip")
        event = log.get("event_type")
        message = log.get("message")

        if not ip or not event:
            continue

        # Brute Force
        if event == "FAILED_LOGIN":
            failed_login_counter[ip] += 1

        # Port Scan
        if event == "PORT_SCAN":
            port_scan_counter[ip].add(message)

    # Brute Force Alert
    for ip, count in failed_login_counter.items():
        if count >= 5:
            alerts.append({
                "type": "BRUTE_FORCE",
                "source_ip": ip,
                "severity": "high",
                "details": f"{count} failed login attempts detected"
            })

    # Port Scan Alert
    for ip, ports in port_scan_counter.items():
        if len(ports) >= 5:
            alerts.append({
                "type": "PORT_SCAN",
                "source_ip": ip,
                "severity": "medium",
                "details": f"{len(ports)} ports scanned"
            })

    # =========================
    # 2. AI Detection
    # =========================
    for log in logs:
        try:
            result = predict_log(log)

            if result == "ANOMALY":
                alerts.append({
                    "type": "AI_ANOMALY",
                    "source_ip": log.get("source_ip"),
                    "severity": "low",
                    "details": "Detected by AI"
                })

        except Exception as e:
            print("AI error:", e)

    # =========================
    # 3. Hybrid Logic
    # =========================
    for alert in alerts:
        if alert["type"] == "BRUTE_FORCE":
            for a in alerts:
                if a["type"] == "AI_ANOMALY" and a["source_ip"] == alert["source_ip"]:
                    alert["severity"] = "high"
                    alert["details"] = "Brute force confirmed by AI"

    return alerts
