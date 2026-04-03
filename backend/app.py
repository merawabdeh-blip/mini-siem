from fastapi import FastAPI
from ml.predict import predict_log
from datetime import datetime

app = FastAPI()

# تخزين alerts مؤقت
alerts = []

@app.post("/log")
def receive_log(log: dict):
    result = predict_log(log)

    if result == "ATTACK":
        alert = {
            "time": str(datetime.now()),
            "log": log,
            "status": "ATTACK"
        }
        alerts.append(alert)
        return {"message": "🚨 ALERT GENERATED", "alert": alert}

    return {"message": "Normal log"}

@app.get("/alerts")
def get_alerts():
    return alerts
