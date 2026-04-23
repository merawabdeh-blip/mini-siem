import joblib
import pandas as pd
import ipaddress

MODEL_PATH = "ml/model.pkl"
ENCODERS_PATH = "ml/encoders.pkl"

model, feature_columns, medians = joblib.load(MODEL_PATH)
encoders = joblib.load(ENCODERS_PATH)


def safe_ip_to_int(ip: str) -> int:
    try:
        return int(ipaddress.ip_address(ip))
    except Exception:
        return 0


def build_feature_row_from_log(log: dict):
    row = {i: 0 for i in range(48)}

    source = str(log.get("source", "unknown")).lower()
    source_ip = str(log.get("source_ip", "0.0.0.0"))
    event_type = str(log.get("event_type", "UNKNOWN")).upper()
    message = str(log.get("message", ""))
    severity = str(log.get("severity", "low")).lower()

    msg = message.lower()

    # columns inspired by UNSW structure, but mapped from live SIEM logs
    row[0] = source_ip
    row[1] = len(message)
    row[2] = source
    row[3] = len(source_ip)
    row[4] = source
    row[5] = event_type
    row[6] = len(message) / 10 if message else 0
    row[7] = len(message)
    row[8] = len(message) * 2

    # keyword indicators
    row[9] = 1 if ("failed" in msg or "invalid" in msg) else 0
    row[10] = 1 if "login" in msg else 0
    row[11] = 1 if "brute" in msg else 0
    row[12] = 1 if ("scan" in msg or "nmap" in msg) else 0
    row[13] = severity

    # stronger security signal instead of raw IP modulo
    row[14] = 1 if any(x in msg for x in ["attack", "brute", "scan", "failed"]) else 0

    row[15] = 1 if severity == "high" else 0
    row[16] = 1 if severity == "medium" else 0
    row[17] = 1 if severity == "low" else 0

    row[18] = 1 if event_type == "FAILED_LOGIN" else 0
    row[19] = 1 if event_type == "BRUTE_FORCE" else 0
    row[20] = 1 if event_type == "PORT_SCAN" else 0
    row[21] = 1 if event_type == "SUCCESS_LOGIN" else 0
    row[22] = 1 if event_type == "PRIVILEGE_ESCALATION" else 0
    row[23] = 1 if event_type == "SYSTEM_ACTIVITY" else 0
    row[24] = 1 if event_type == "ATTACK" else 0
    row[25] = 1 if event_type == "MALWARE" else 0

    row[26] = 1 if "sudo" in msg else 0
    row[27] = 1 if "root" in msg else 0
    row[28] = 1 if "password" in msg else 0
    row[29] = 1 if "attack" in msg else 0
    row[30] = 1 if ("malware" in msg or "virus" in msg or "trojan" in msg) else 0
    row[31] = 1 if source == "auth" else 0
    row[32] = 1 if source == "web" else 0
    row[33] = 1 if source == "network" else 0
    row[34] = 1 if source == "system" else 0
    row[35] = 1 if source == "syslog" else 0
    row[36] = 1 if source == "api" else 0
    row[37] = 1 if source == "wazuh" else 0

    # message-based intensity signals
    row[38] = msg.count("failed")
    row[39] = msg.count("scan")
    row[40] = msg.count("login")
    row[41] = msg.count("error")
    row[42] = msg.count("warning")
    row[43] = len(msg.split())

    # keep remaining columns present
    row[44] = 1 if "session opened" in msg else 0
    row[45] = 1 if "http" in msg else 0
    row[46] = 1 if "port" in msg else 0
    row[47] = 0

    return row


def preprocess_runtime_row(row: dict):
    df = pd.DataFrame([row])

    df = df[feature_columns]

    object_cols = df.select_dtypes(include=["object"]).columns.tolist()
    for col in object_cols:
        df[col] = df[col].astype(str).fillna("missing")
        mapping = encoders.get(col, {})
        df[col] = df[col].map(lambda v: mapping.get(v, -1))

    df = df.apply(pd.to_numeric, errors="coerce")
    df = df.fillna(pd.Series(medians))

    return df


def predict_log(log: dict):
    try:
        row = build_feature_row_from_log(log)
        df = preprocess_runtime_row(row)

        score = float(model.decision_function(df)[0])

        if score < -0.08:
            label = "ATTACK"
        elif score < 0:
            label = "SUSPICIOUS"
        else:
            label = "NORMAL"

        return {
            "label": label,
            "score": score
        }

    except Exception as e:
        return {
            "label": "ERROR",
            "score": None,
            "error": str(e)
        }


if __name__ == "__main__":
    sample = {
        "source": "auth",
        "source_ip": "192.168.1.99",
        "event_type": "BRUTE_FORCE",
        "message": "brute force attack from 192.168.1.99",
        "severity": "high"
    }
    print(predict_log(sample))
