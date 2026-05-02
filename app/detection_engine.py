from collections import defaultdict
from app.ai_analyzer import predict_log

# =========================
# Global Counters
# =========================
failed_login_counter = defaultdict(int)
port_scan_counter = defaultdict(set)

# Correlation memory: track event types seen per IP
ip_event_history = defaultdict(set)

# =========================
# Thresholds
# =========================
BRUTE_FORCE_THRESHOLD = 5
PORT_SCAN_THRESHOLD = 5

# If the same IP shows these attack types, raise a stronger alert
MULTI_STAGE_EVENTS = {"FAILED_LOGIN", "BRUTE_FORCE", "PORT_SCAN"}


def detect_rule_based(logs):
    alerts = []

    for log in logs:
        ip = log.get("source_ip")
        event = log.get("event_type")
        message = log.get("message", "")

        if not ip or not event:
            continue

        event = str(event).upper()
        ip_event_history[ip].add(event)

        # Count failed logins per IP
        if event == "FAILED_LOGIN":
            failed_login_counter[ip] += 1

        # Track unique scanned ports/messages per IP
        elif event == "PORT_SCAN":
            port_scan_counter[ip].add(message)

        # Successful login after failed attempts
        elif event in ["LOGIN_SUCCESS", "SUCCESS_LOGIN"]:
            if failed_login_counter[ip] >= BRUTE_FORCE_THRESHOLD:
                alerts.append({
                    "type": "SUSPICIOUS_LOGIN_SUCCESS",
                    "source_ip": ip,
                    "severity": "high",
                    "details": f"Successful login after {failed_login_counter[ip]} failed attempts"
                })

    # Brute Force Alerts
    for ip, count in failed_login_counter.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "type": "BRUTE_FORCE",
                "source_ip": ip,
                "severity": "high",
                "details": f"{count} failed login attempts detected"
            })
            ip_event_history[ip].add("BRUTE_FORCE")

    # Port Scan Alerts
    for ip, ports in port_scan_counter.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            alerts.append({
                "type": "PORT_SCAN",
                "source_ip": ip,
                "severity": "high",
                "details": f"{len(ports)} unique ports scanned"
            })
            ip_event_history[ip].add("PORT_SCAN")

    return alerts


def detect_correlation_alerts():
    alerts = []

    for ip, events in ip_event_history.items():
        matched_events = MULTI_STAGE_EVENTS.intersection(events)

        if len(matched_events) >= 3:
            alerts.append({
                "type": "MULTI_STAGE_ATTACK",
                "source_ip": ip,
                "severity": "critical",
                "details": f"Multiple attack stages detected from same IP: {', '.join(sorted(matched_events))}"
            })

    return alerts


def detect_ai_anomalies(logs):
    alerts = []

    for log in logs:
        try:
            result = predict_log(log)

            if isinstance(result, dict):
                if result.get("label") == "ANOMALY":
                    alerts.append({
                        "type": "AI_ANOMALY",
                        "source_ip": log.get("source_ip"),
                        "severity": "medium",
                        "details": f"Detected by AI (score: {result.get('score', 'N/A')})"
                    })

            elif result == "ANOMALY":
                alerts.append({
                    "type": "AI_ANOMALY",
                    "source_ip": log.get("source_ip"),
                    "severity": "medium",
                    "details": "Detected by AI"
                })

        except Exception as e:
            print("AI error:", e)

    return alerts


def apply_hybrid_logic(alerts):
    updated_alerts = []

    for alert in alerts:
        updated_alert = alert.copy()

        if alert["type"] == "BRUTE_FORCE":
            for other_alert in alerts:
                if (
                    other_alert["type"] == "AI_ANOMALY"
                    and other_alert["source_ip"] == alert["source_ip"]
                ):
                    updated_alert["severity"] = "critical"
                    updated_alert["details"] = "Brute force confirmed by AI"
                    break

        elif alert["type"] == "PORT_SCAN":
            for other_alert in alerts:
                if (
                    other_alert["type"] == "AI_ANOMALY"
                    and other_alert["source_ip"] == alert["source_ip"]
                ):
                    updated_alert["severity"] = "high"
                    updated_alert["details"] = "Port scan confirmed by AI"
                    break

        elif alert["type"] == "SUSPICIOUS_LOGIN_SUCCESS":
            updated_alert["severity"] = "critical"

        elif alert["type"] == "MULTI_STAGE_ATTACK":
            updated_alert["severity"] = "critical"

        updated_alerts.append(updated_alert)

    return updated_alerts


def remove_duplicate_alerts(alerts):
    unique_alerts = []
    seen = set()

    for alert in alerts:
        key = (alert["type"], alert["source_ip"], alert["details"])
        if key not in seen:
            seen.add(key)
            unique_alerts.append(alert)

    return unique_alerts


def run_detection(logs):
    if not logs:
        return []

    rule_based_alerts = detect_rule_based(logs)
    ai_alerts = detect_ai_anomalies(logs)
    correlation_alerts = detect_correlation_alerts()

    all_alerts = rule_based_alerts + ai_alerts + correlation_alerts
    all_alerts = apply_hybrid_logic(all_alerts)
    all_alerts = remove_duplicate_alerts(all_alerts)

    return all_alerts
