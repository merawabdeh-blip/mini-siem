from ml.predict import predict_log


# More negative score = more suspicious.
# Tuned to reduce false positives from normal live traffic.
CRITICAL_THRESHOLD = -0.18
ATTACK_THRESHOLD = -0.10
SUSPICIOUS_THRESHOLD = -0.07

BORDERLINE_NORMAL_EVENTS = {
    "TCP_ACTIVITY",
    "UDP_ACTIVITY",
    "ICMP_ACTIVITY",
    "SUCCESS_LOGIN",
    "LOGIN_SUCCESS",
}

SECURITY_EVENTS = {
    "PORT_SCAN",
    "BRUTE_FORCE",
    "FAILED_LOGIN",
    "SUSPICIOUS_LOGIN_SUCCESS",
    "MULTI_STAGE_ATTACK",
}


def analyze_log_with_ai(normalized_log):
    result = predict_log(normalized_log)

    score = result.get("score")
    event_type = str(normalized_log.get("event_type", "UNKNOWN")).upper()

    if score is None:
        label = "ERROR"
    else:
        if score < CRITICAL_THRESHOLD:
            label = "CRITICAL"
        elif score < ATTACK_THRESHOLD:
            label = "ATTACK"
        elif score < SUSPICIOUS_THRESHOLD:
            label = "SUSPICIOUS"
        else:
            label = "NORMAL"

        # Normal live traffic often gets borderline scores.
        # Keep it normal unless it is clearly below ATTACK threshold.
        if event_type in BORDERLINE_NORMAL_EVENTS and score > ATTACK_THRESHOLD:
            label = "NORMAL"

        # Security events should still appear as suspicious.
        if event_type in SECURITY_EVENTS and label == "NORMAL":
            label = "SUSPICIOUS"

    print(f"ML RESULT: {label} | event_type={event_type} | score={score}")

    return {
        "label": label,
        "score": score
    }
