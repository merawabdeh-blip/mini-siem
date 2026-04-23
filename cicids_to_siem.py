import pandas as pd
import requests
import time

SIEM_URL = "http://127.0.0.1:8000/logs/log"
TOKEN = input("Enter your token: ").strip()

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

FILE = "cicids2017_attacks.csv"   # إذا عندك full dataset حطي اسمه هون

df = pd.read_csv(FILE)

print("Total rows:", len(df))

label_col = "Label"

count = 0
sent = 0

for _, row in df.iterrows():
    label = str(row[label_col]).strip()

    # 🔥 تجاهل benign
    if label.upper() == "BENIGN":
        continue

    payload = {
        "message": f"{label} detected from dataset",
        "source": "cicids2017",
        "source_ip": f"10.0.0.{count % 255}"
    }

    try:
        r = requests.post(SIEM_URL, json=payload, headers=HEADERS, timeout=5)

        if r.status_code == 200:
            sent += 1

        print(f"{r.status_code} | {label}")

    except Exception as e:
        print("Error:", e)

    count += 1

    # 🔥 batch control (مهم جدًا)
    if count % 100 == 0:
        print(f"--- Sent {sent} attacks so far ---")
        time.sleep(1)   # يعطي السيرفر وقت

print(f"\nDONE: Sent {sent} attack logs out of {len(df)} rows")
