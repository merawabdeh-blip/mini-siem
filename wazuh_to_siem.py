import json
import time
import requests
import os

WAZUH_ALERTS = "/var/ossec/logs/alerts/alerts.json"
SIEM_URL = "http://127.0.0.1:8000/logs/log"
TOKEN = os.getenv("TOKEN")

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

ALLOWED_DESCRIPTIONS = [
    "Failed login detected",
    "Brute force attack detected",
    "Port scan detected"
]
EVENT_TYPE_MAP = {
    "Failed login detected": "FAILED_LOGIN",
    "Brute force attack detected": "BRUTE_FORCE",
    "Port scan detected": "PORT_SCAN"
}

def send_to_siem(alert: dict) -> None:
    rule = alert.get("rule", {})
    data = alert.get("data", {})

    description = rule.get("description", "")

    # نفلتر بس alerts تبعتنا
    if description not in ALLOWED_DESCRIPTIONS:
        return

    payload = {
        "message": alert.get("full_log", ""),
        "source": "wazuh",
        "source_ip": data.get("srcip", "127.0.0.1"),
        "event_type": EVENT_TYPE_MAP.get(description, "UNKNOWN"),
        "severity": str(rule.get("level", "low")),
        "timestamp": alert.get("timestamp", "")
    }

    try:
        response = requests.post(
            SIEM_URL,
            json=payload,
            headers=HEADERS,
            timeout=5
        )
        print(f"Sent to SIEM: {response.status_code} | {payload['event_type']} | {response.text}")
    except Exception as e:
        print("Error sending to SIEM:", e)


def follow_file(path: str) -> None:
    print(f"Opening Wazuh alerts file: {path}")

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
            except json.JSONDecodeError:
                continue
            except Exception as e:
                print("Error parsing alert:", e)


def main() -> None:
    print("Watching Wazuh alerts and forwarding to SIEM...")
    follow_file(WAZUH_ALERTS)


if __name__ == "__main__":
    main()
