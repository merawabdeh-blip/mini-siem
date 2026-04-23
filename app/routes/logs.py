from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path
from datetime import datetime

from app.database import get_db
from app.utils.normalizer import normalize_log
from app.detection_engine import run_detection
from app.ai_analyzer import analyze_log_with_ai
from app.dependencies import require_role
from app.audit import log_audit_event
from app.validators import validate_log_input

router = APIRouter(prefix="/logs")


@router.post("/log")
def receive_log(
    log: dict,
    current_user: dict = Depends(require_role(["analyst", "admin"]))
):
    is_valid, validation_result = validate_log_input(log)
    if not is_valid:
        raise HTTPException(status_code=400, detail=validation_result)

    log["message"] = validation_result["message"]
    log["source"] = validation_result["source"]
    if validation_result["source_ip"]:
        log["source_ip"] = validation_result["source_ip"]

    normalized = normalize_log(log)

    db_gen = get_db()
    db = next(db_gen)
    cursor = db.cursor()

    normalized["timestamp"] = datetime.utcnow().isoformat()

    try:
        ai_result = analyze_log_with_ai(normalized)
        prediction = ai_result.get("label", "UNKNOWN")
        ai_score = ai_result.get("score")
        print(f"ML RESULT: {prediction} | score={ai_score}")
    except Exception as e:
        print("ML ERROR:", e)
        prediction = "UNKNOWN"
        ai_score = None

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

    alerts = run_detection([normalized])

    # AI-based hybrid alerting
    if prediction in ["ATTACK", "CRITICAL"]:
        severity = "high" if prediction == "ATTACK" else "critical"

        alerts.append({
            "type": "AI_ANOMALY",
            "source_ip": normalized["source_ip"],
            "details": f"AI detected anomaly: {normalized['message']}",
            "severity": severity
        })

    elif prediction == "SUSPICIOUS" and normalized["event_type"] in [
        "BRUTE_FORCE", "PORT_SCAN", "PRIVILEGE_ESCALATION", "FAILED_LOGIN"
    ]:
        alerts.append({
            "type": "AI_SUSPICIOUS",
            "source_ip": normalized["source_ip"],
            "details": f"AI marked suspicious activity: {normalized['message']}",
            "severity": "medium"
        })

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
        "ai_score": ai_score,
        "alerts_generated": len(alerts)
    }


@router.get("/")
def get_logs(current_user: dict = Depends(require_role(["analyst", "admin"]))):
    log_audit_event(current_user["sub"], "VIEW_LOGS", "/logs/")

    db_gen = get_db()
    db = next(db_gen)
    cursor = db.cursor()

    cursor.execute("SELECT * FROM logs ORDER BY id DESC")
    rows = cursor.fetchall()
    logs = [dict(row) for row in rows]

    db.close()
    return logs


@router.get("/alerts")
def get_alerts(current_user: dict = Depends(require_role(["viewer", "analyst", "admin"]))):
    log_audit_event(current_user["sub"], "VIEW_ALERTS", "/logs/alerts")

    db_gen = get_db()
    db = next(db_gen)
    cursor = db.cursor()

    cursor.execute("SELECT * FROM alerts ORDER BY id DESC")
    rows = cursor.fetchall()
    alerts = [dict(row) for row in rows]

    db.close()
    return alerts


@router.get("/dashboard")
def dashboard():
    return FileResponse(Path("templates/dashboard.html"))


@router.get("/audit")
def get_audit_logs(current_user: dict = Depends(require_role(["admin"]))):
    log_audit_event(current_user["sub"], "VIEW_AUDIT_LOGS", "/logs/audit")

    db_gen = get_db()
    db = next(db_gen)
    cursor = db.cursor()

    cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC")
    rows = cursor.fetchall()
    audit_logs = [dict(row) for row in rows]

    db.close()
    return audit_logs


@router.post("/reset-demo")
def reset_demo(current_user: dict = Depends(require_role(["admin"]))):
    db_gen = get_db()
    db = next(db_gen)
    cursor = db.cursor()

    cursor.execute("DELETE FROM logs")
    cursor.execute("DELETE FROM alerts")
    cursor.execute("DELETE FROM audit_logs")

    db.commit()
    db.close()

    return {
        "message": "Demo data reset successfully",
        "tables_cleared": ["logs", "alerts", "audit_logs"]
    }
