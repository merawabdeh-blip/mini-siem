from collections import defaultdict, Counter
from app.ai_analyzer import predict_log


def run_detection(logs):
    alerts = []

    # =========================
    # 1. Rule-Based Detection (simple counter)
    # =========================

    ip_counter = Counter()

    for log in logs:
        ip = log.get("source_ip")
        if ip:
            ip_counter[ip] += 1

    for ip, count in ip_counter.items():
        if count > 10:
            alerts.append({
                "type": "Brute Force",
                "source_ip": ip,
                "severity": "medium",
                "details": f"{count} requests detected"
            })

    # =========================
    # 2. Advanced Rules
    # =========================

    failed_login_counter = defaultdict(int)
    port_scan_counter = defaultdict(set)

    for log in logs:
        ip = log.get("source_ip")
        event = log.get("event_type")

        # Brute Force
        if event in ["FAILED_LOGIN", "login_failure"]:
            failed_login_counter[ip] += 1

        # Port Scan
        if event == "port_scan":
            port = log.get("message")
            port_scan_counter[ip].add(port)

    # Brute Force Alert
    for ip, count in failed_login_counter.items():
        if count >= 5:
            alerts.append({
                "type": "BRUTE_FORCE",
                "source_ip": ip,
                "count": count,
                "severity": "high"
            })

    # Port Scan Alert
    for ip, ports in port_scan_counter.items():
        if len(ports) >= 5:
            alerts.append({
                "type": "PORT_SCAN",
                "source_ip": ip,
                "ports_scanned": len(ports),
                "severity": "medium"
            })

    # =========================
    # 3. AI Detection
    # =========================

    for log in logs:
        try:
            result = predict_log(log)

            if result == "ANOMALY":
                alerts.append({
                    "type": "AI Anomaly",
                    "source_ip": log.get("source_ip"),
                    "severity": "low",
                    "details": "Detected by AI"
                })

        except Exception as e:
            print("AI error:", e)

    # =========================
    # 4. Hybrid Logic
    # =========================

    for alert in alerts:
        if alert["type"] == "BRUTE_FORCE":
            for a in alerts:
                if a["type"] == "AI Anomaly" and a["source_ip"] == alert["source_ip"]:
                    alert["severity"] = "high"

    return alerts
