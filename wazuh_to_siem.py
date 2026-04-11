import json
import time
import requests

WAZUH_ALERTS = "/var/ossec/logs/alerts/alerts.json"
SIEM_URL = "http://127.0.0.1:8000/logs/log"


def send_to_siem(alert: dict) -> None:
    rule = alert.get("rule", {})
    data = alert.get("data", {})

    payload = {
        "message": alert.get("full_log", ""),
        "source": "wazuh",
        "source_ip": data.get("srcip", "127.0.0.1"),
        "event_type": rule.get("description", "UNKNOWN"),
        "severity": str(rule.get("level", "low")),
        "timestamp": alert.get("timestamp", "")
    }

    try:
        response = requests.post(SIEM_URL, json=payload, timeout=5)
        print(f"Sent to SIEM: {response.status_code} | {payload['event_type']}")
    except Exception as e:
        print("Error sending to SIEM:", e)


def follow_file(path: str) -> None:
    with open(path, "r") as f:
        f.seek(0, 2)

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            try:
                alert = json.loads(line.strip())
                send_to_siem(alert)
            except Exception as e:
                print("Error parsing alert:", e)


if __name__ == "__main__":
    print("Watching Wazuh alerts and forwarding to SIEM...")
    follow_file(WAZUH_ALERTS)
