import requests
import time
import random

URL = "http://127.0.0.1:8000/logs/log"

def send_log(log):
    try:
        requests.post(URL, json=log)
        print("Sent:", log)
    except Exception as e:
        print("Error:", e)

def brute_force(ip):
    for i in range(6):
        log = {
            "source": "auth",
            "source_ip": ip,
            "event_type": "FAILED_LOGIN",
            "message": "login failed"
        }
        send_log(log)
        time.sleep(0.2)

def port_scan(ip):
    for port in range(20, 30):
        log = {
            "source": "network",
            "source_ip": ip,
            "event_type": "port_scan",
            "message": str(port)
        }
        send_log(log)
        time.sleep(0.1)

def normal_traffic():
    ip = f"192.168.1.{random.randint(1,255)}"
    log = {
        "source": "web",
        "source_ip": ip,
        "event_type": "LOGIN_SUCCESS",
        "message": "user logged in"
    }
    send_log(log)

def run():
    while True:
        ip_attack = f"192.168.1.{random.randint(100,200)}"

        if random.random() > 0.5:
            brute_force(ip_attack)
        else:
            port_scan(ip_attack)

        for _ in range(3):
            normal_traffic()

        print("------ cycle done ------\n")
        time.sleep(2)

if __name__ == "__main__":
    run()
