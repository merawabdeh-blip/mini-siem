from collections import defaultdict

def run_detection(logs):

    alerts = []

    failed_login_counter = defaultdict(int)
    port_scan_counter = defaultdict(set)

    for log in logs:
        ip = log.get("source_ip")
        event = log.get("event_type")

        # 🔥 Brute Force
        if event in ["FAILED_LOGIN", "login_failure"]:
            failed_login_counter[ip] += 1

        # 🔥 Port Scan
        if event == "port_scan":
            port = log.get("message")
            port_scan_counter[ip].add(port)

    # 🔥 Brute Force Alert
    for ip, count in failed_login_counter.items():
        if count >= 5:
            alerts.append({
                "type": "BRUTE_FORCE",
                "source_ip": ip,
                "count": count,
                "severity": "high"
            })

    # 🔥 Port Scan Alert
    for ip, ports in port_scan_counter.items():
        if len(ports) >= 5:
            alerts.append({
                "type": "PORT_SCAN",
                "source_ip": ip,
                "ports_scanned": len(ports),
                "severity": "medium"
            })

    return alerts
