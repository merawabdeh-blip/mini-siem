from ml.predict import predict_log


def analyze_log_with_ai(normalized_log):
    result = predict_log(normalized_log)

    score = result.get("score")
    event_type = str(normalized_log.get("event_type", "UNKNOWN")).upper()

    if score is None:
        label = "ERROR"
    else:
        if score < -0.18:
            label = "CRITICAL"
        elif score < -0.08:
            label = "ATTACK"
        elif score < -0.03:
            label = "SUSPICIOUS"
        else:
            label = "NORMAL"

        # تقليل false positives للأحداث الطبيعية
        if event_type == "SUCCESS_LOGIN" and score > -0.12:
            label = "NORMAL"

    print(f"ML RESULT: {label} | score={score}")

    return {
        "label": label,
        "score": score
    }
