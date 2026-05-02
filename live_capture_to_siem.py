from scapy.all import sniff, IP, TCP, UDP, ICMP
import requests
from datetime import datetime

SIEM_URL = "http://127.0.0.1:8000/logs/log"
TOKEN = input("Enter your token: ").strip()

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}


def classify_packet(packet):
    if IP not in packet:
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = "UNKNOWN"
    message = ""

    if TCP in packet:
        proto = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = str(packet[TCP].flags)

        message = (
            f"Live TCP packet detected "
            f"from {src_ip}:{sport} to {dst_ip}:{dport} flags={flags}"
        )

    elif UDP in packet:
        proto = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport

        message = (
            f"Live UDP packet detected "
            f"from {src_ip}:{sport} to {dst_ip}:{dport}"
        )

    elif ICMP in packet:
        proto = "ICMP"
        message = f"Live ICMP packet detected from {src_ip} to {dst_ip}"

    else:
        message = f"Live IP packet detected from {src_ip} to {dst_ip}"

    return {
        "message": message,
        "source": "live_capture",
        "source_ip": src_ip,
        "timestamp": datetime.utcnow().isoformat(),
        "protocol": proto
    }


def send_to_siem(payload):
    try:
        response = requests.post(
            SIEM_URL,
            json=payload,
            headers=HEADERS,
            timeout=5
        )
        print(response.status_code, "|", payload["message"][:90])
    except Exception as e:
        print("Error sending packet to SIEM:", e)


def handle_packet(packet):
    payload = classify_packet(packet)
    if payload:
        send_to_siem(payload)


if __name__ == "__main__":
    print("Starting live packet capture...")
    print("Press CTRL+C to stop.")

    sniff(
        filter="ip",
        prn=handle_packet,
        store=False
    )
