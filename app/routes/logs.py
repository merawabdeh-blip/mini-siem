from fastapi import APIRouter
from fastapi.responses import FileResponse
from pathlib import Path
from app.database import get_db
from app.utils.normalizer import normalize_log
from app.detection_engine import run_detection
from datetime import datetime
from ml.predict import predict_log  # 🔥 ML

router = APIRouter(prefix="/logs")


# ==============================
# استقبال log جديد
# ==============================
@router.post("/log")
def receive_log(log: dict):

    normalized = normalize_log(log)

    db_gen = get_db()
    db = next(db_gen)
    cursor = db.cursor()

    # إضافة timestamp
    normalized["timestamp"] = datetime.utcnow().isoformat()

    # 🔥 ML Prediction (بدون تخريب النظام)
    try:
        prediction = predict_log(log)
        print("ML RESULT:", prediction)
    except Exception as e:
        print("ML ERROR:", e)
        prediction = "UNKNOWN"

    # 🔥 تعديل severity و event_type حسب ML
    if prediction == "ATTACK":
        normalized["severity"] = "high"
        normalized["event_type"] = "attack"
    else:
        normalized["severity"] = "low"
        normalized["event_type"] = "normal"

    # ==============================
    # إدخال log
    # ==============================
    cursor.execute("""
        INSERT INTO logs (source, source_ip, event_type, message, severity, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        normalized.get("source"),
        normalized.get("source_ip"),
        normalized.get("event_type"),
        normalized.get("message"),
        normalized.get("severity"),
        normalized.get("timestamp")
    ))

    db.commit()

    # ==============================
    # تشغيل detection (زي ما هو)
    # ==============================
    cursor.execute("SELECT * FROM logs")
    rows = cursor.fetchall()
    logs = [dict(row) for row in rows]

    alerts = run_detection(logs)

    # ==============================
    # حفظ alerts
    # ==============================
    for alert in alerts:
        cursor.execute("""
            INSERT INTO alerts (type, source_ip, description, severity, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (
            alert.get("type"),
            alert.get("source_ip"),
            str(alert),
            alert.get("severity"),
            datetime.utcnow().isoformat()
        ))

    db.commit()
    db.close()

    return {
        "message": "Log received",
        "prediction": prediction  # 🔥 أضفناها بالresponse
    }


# ==============================
# عرض logs
# ==============================
@router.get("/")
def get_logs():
    db_gen = get_db()
    db = next(db_gen)
    cursor = db.cursor()

    cursor.execute("SELECT * FROM logs ORDER BY id DESC")
    rows = cursor.fetchall()

    logs = [dict(row) for row in rows]

    db.close()
    return logs


# ==============================
# عرض alerts
# ==============================
@router.get("/alerts")
def get_alerts():
    db_gen = get_db()
    db = next(db_gen)
    cursor = db.cursor()

    cursor.execute("SELECT * FROM alerts ORDER BY id DESC")
    rows = cursor.fetchall()

    alerts = [dict(row) for row in rows]

    db.close()
    return alerts


# ==============================
# Dashboard
# ==============================
@router.get("/dashboard")
def dashboard():
    return FileResponse(Path("templates/dashboard.html"))
