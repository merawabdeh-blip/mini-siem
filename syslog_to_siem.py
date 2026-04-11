import requests
import time

URL = "http://127.0.0.1:8000/logs/log"

with open("/var/log/syslog", "r") as f:
    f.seek(0, 2)  # go to end of file

    while True:
        line = f.readline()

        if not line:
            time.sleep(0.5)
            continue

        log = {
            "message": line.strip(),
            "source": "syslog"
        }

        try:
            response = requests.post(URL, json=log)

            if response.status_code == 200:
                print("Sent:", line.strip())
            else:
                print("Failed:", response.status_code)

        except Exception as e:
            print("Error:", e)
