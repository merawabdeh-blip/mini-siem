from fastapi import APIRouter
from fastapi.responses import FileResponse
from pathlib import Path
from datetime import datetime

from app.database import get_db
from app.utils.normalizer import normalize_log
from app.detection_engine import run_detection
from app.ai_analyzer import predict_log

from fastapi import Depends
from app.dependencies import require_role

router = APIRouter(prefix="/logs")


# ==============================
# استقبال log جديد
# ==============================
@router.post("/log")
def receive_log(
    log: dict,
    current_user: dict = Depends(require_role(["analyst", "admin"]))
):
    normalized = normalize_log(log)

    db_gen = get_db()
    db = next(db_gen)
    cursor = db.cursor()

    # إضافة timestamp
    normalized["timestamp"] = datetime.utcnow().isoformat()

    # ==============================
    # ML Prediction
    # ==============================
    try:
        prediction_result = predict_log(normalized)
        if isinstance(prediction_result, dict):
            prediction = prediction_result.get("label", "UNKNOWN")
        else:
            prediction = prediction_result
        print("ML RESULT:", prediction)
    except Exception as e:
        print("ML ERROR:", e)
        prediction = "UNKNOWN"

    # ==============================
    # إدخال log
    # ==============================
    cursor.execute(
        """
        INSERT INTO logs (source, source_ip, event_type, message, severity, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            normalized["source"],
            normalized["source_ip"],
            normalized["event_type"],
            normalized["message"],
            normalized["severity"],
            normalized["timestamp"],
        ),
    )

    # ==============================
    # تشغيل detection
    # ==============================
    alerts = run_detection([normalized])

    # ==============================
    # حفظ alerts
    # ==============================
    for alert in alerts:
        cursor.execute(
            """
            INSERT INTO alerts (type, source_ip, description, severity, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                alert.get("type"),
                alert.get("source_ip"),
                alert.get("details"),
                alert.get("severity"),
                datetime.utcnow().isoformat(),
            ),
        )

    db.commit()
    db.close()

    return {
        "message": "Log received",
        "prediction": prediction,
        "alerts_generated": len(alerts)
    }


# ==============================
# عرض logs
# ==============================
@router.get("/")
def get_logs(current_user: dict = Depends(require_role(["analyst", "admin"]))):
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
def get_alerts(current_user: dict = Depends(require_role(["viewer", "analyst", "admin"]))):
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
def dashboard(current_user: dict = Depends(require_role(["viewer", "analyst", "admin"]))):
    return FileResponse(Path("templates/dashboard.html"))
