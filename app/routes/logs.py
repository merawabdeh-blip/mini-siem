from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from pathlib import Path
from datetime import datetime
from io import StringIO, BytesIO
import csv
import shutil
import hashlib

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

from app.database import get_db
from app.dependencies import require_role
from app.utils.normalizer import normalize_log
from app.detection_engine import run_detection
from app.ai_analyzer import analyze_log_with_ai
from app.audit import log_audit_event
from app.validators import validate_log_input

router = APIRouter(prefix="/logs")


def calculate_risk_score(event_type: str, prediction: str) -> int:
    base_scores = {
        "FAILED_LOGIN": 40,
        "PORT_SCAN": 60,
        "BRUTE_FORCE": 80,
        "PRIVILEGE_ESCALATION": 90,
        "SUCCESS_LOGIN": 10,
        "UNKNOWN": 20,
        "ATTACK": 30,
    }

    score = base_scores.get(str(event_type).upper(), 20)

    if prediction == "SUSPICIOUS":
        score += 10
    elif prediction == "ATTACK":
        score += 20
    elif prediction == "CRITICAL":
        score += 30

    return min(score, 100)


def build_logs_query(
    source: str | None = None,
    severity: str | None = None,
    event_type: str | None = None,
    source_ip: str | None = None,
    q: str | None = None,
):
    query = "SELECT * FROM logs"
    conditions = []
    params = []

    if source:
        conditions.append("LOWER(source) = LOWER(?)")
        params.append(source)

    if severity:
        conditions.append("LOWER(severity) = LOWER(?)")
        params.append(severity)

    if event_type:
        conditions.append("LOWER(event_type) = LOWER(?)")
        params.append(event_type)

    if source_ip:
        conditions.append("source_ip = ?")
        params.append(source_ip)

    if q:
        conditions.append(
            "(LOWER(message) LIKE LOWER(?) OR LOWER(event_type) LIKE LOWER(?) OR LOWER(source) LIKE LOWER(?) OR LOWER(source_ip) LIKE LOWER(?))"
        )
        keyword = f"%{q}%"
        params.extend([keyword, keyword, keyword, keyword])

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY id DESC"
    return query, params


def build_alerts_query(
    severity: str | None = None,
    alert_type: str | None = None,
    source_ip: str | None = None,
    q: str | None = None,
):
    query = "SELECT * FROM alerts"
    conditions = []
    params = []

    if severity:
        conditions.append("LOWER(severity) = LOWER(?)")
        params.append(severity)

    if alert_type:
        conditions.append("LOWER(type) = LOWER(?)")
        params.append(alert_type)

    if source_ip:
        conditions.append("source_ip = ?")
        params.append(source_ip)

    if q:
        conditions.append(
            "(LOWER(description) LIKE LOWER(?) OR LOWER(type) LIKE LOWER(?) OR LOWER(source_ip) LIKE LOWER(?))"
        )
        keyword = f"%{q}%"
        params.extend([keyword, keyword, keyword])

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY id DESC"
    return query, params


def rows_to_csv(rows: list[dict], fieldnames: list[str]) -> StringIO:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({k: row.get(k, "") for k in fieldnames})
    output.seek(0)
    return output


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
    normalized["timestamp"] = datetime.utcnow().isoformat()

    message_hash = hashlib.sha256(normalized["message"].encode()).hexdigest()

    db_gen = get_db()
    db = next(db_gen)
    cursor = db.cursor()

    try:
        ai_result = analyze_log_with_ai(normalized)
        prediction = ai_result.get("label", "UNKNOWN")
        ai_score = ai_result.get("score")
        print(f"ML RESULT: {prediction} | score={ai_score}")
    except Exception as e:
        print("ML ERROR:", e)
        prediction = "UNKNOWN"
        ai_score = None

    risk_score = calculate_risk_score(normalized["event_type"], prediction)

    cursor.execute(
        """
        INSERT INTO logs (source, source_ip, event_type, message, severity, timestamp, message_hash, user_label)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            normalized["source"],
            normalized["source_ip"],
            normalized["event_type"],
            normalized["message"],
            normalized["severity"],
            normalized["timestamp"],
            message_hash,
            None,
        ),
    )

    alerts = run_detection([normalized])

    if prediction in ["ATTACK", "CRITICAL"]:
        severity = "high" if prediction == "ATTACK" else "critical"

        alerts.append({
            "type": "AI_ANOMALY",
            "source_ip": normalized["source_ip"],
            "details": f"AI detected anomaly: {normalized['message']}",
            "severity": severity
        })

    elif prediction == "SUSPICIOUS" and normalized["event_type"] in [
        "BRUTE_FORCE", "PORT_SCAN", "PRIVILEGE_ESCALATION", "FAILED_LOGIN", "ATTACK"
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
        "risk_score": risk_score,
        "alerts_generated": len(alerts)
    }


@router.get("/")
def get_logs(
    source: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    q: str | None = Query(default=None),
    current_user: dict = Depends(require_role(["analyst", "admin"]))
):
    log_audit_event(current_user["sub"], "VIEW_LOGS", "/logs/")

    db_gen = get_db()
    db = next(db_gen)
    cursor = db.cursor()

    query, params = build_logs_query(source, severity, event_type, source_ip, q)
    cursor.execute(query, params)
    rows = cursor.fetchall()

    logs = []
    for row in rows:
        item = dict(row)
        item["risk_score"] = calculate_risk_score(
            item.get("event_type", "UNKNOWN"),
            "ATTACK" if str(item.get("severity", "")).lower() in ["high", "critical"] else "UNKNOWN"
        )
        logs.append(item)

    db.close()
    return logs


@router.get("/alerts")
def get_alerts(
    severity: str | None = Query(default=None),
    alert_type: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    q: str | None = Query(default=None),
    current_user: dict = Depends(require_role(["viewer", "analyst", "admin"]))
):
    log_audit_event(current_user["sub"], "VIEW_ALERTS", "/logs/alerts")

    db_gen = get_db()
    db = next(db_gen)
    cursor = db.cursor()

    query, params = build_alerts_query(severity, alert_type, source_ip, q)
    cursor.execute(query, params)
    rows = cursor.fetchall()
    alerts = [dict(row) for row in rows]

    db.close()
    return alerts


@router.get("/export/csv")
def export_logs_csv(
    source: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    q: str | None = Query(default=None),
    current_user: dict = Depends(require_role(["analyst", "admin"]))
):
    log_audit_event(current_user["sub"], "EXPORT_LOGS_CSV", "/logs/export/csv")

    db_gen = get_db()
    db = next(db_gen)
    cursor = db.cursor()

    query, params = build_logs_query(source, severity, event_type, source_ip, q)
    cursor.execute(query, params)
    rows = [dict(row) for row in cursor.fetchall()]
    db.close()

    fieldnames = ["id", "source", "source_ip", "event_type", "message", "severity", "timestamp", "message_hash", "user_label"]
    output = rows_to_csv(rows, fieldnames)

    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=logs_export.csv"}
    )


@router.get("/alerts/export/csv")
def export_alerts_csv(
    severity: str | None = Query(default=None),
    alert_type: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    q: str | None = Query(default=None),
    current_user: dict = Depends(require_role(["viewer", "analyst", "admin"]))
):
    log_audit_event(current_user["sub"], "EXPORT_ALERTS_CSV", "/logs/alerts/export/csv")

    db_gen = get_db()
    db = next(db_gen)
    cursor = db.cursor()

    query, params = build_alerts_query(severity, alert_type, source_ip, q)
    cursor.execute(query, params)
    rows = [dict(row) for row in cursor.fetchall()]
    db.close()

    fieldnames = ["id", "type", "source_ip", "description", "severity", "timestamp"]
    output = rows_to_csv(rows, fieldnames)

    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts_export.csv"}
    )


@router.get("/export/pdf")
def export_logs_pdf(
    source: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    q: str | None = Query(default=None),
    current_user: dict = Depends(require_role(["analyst", "admin"]))
):
    log_audit_event(current_user["sub"], "EXPORT_LOGS_PDF", "/logs/export/pdf")

    db_gen = get_db()
    db = next(db_gen)
    cursor = db.cursor()

    query, params = build_logs_query(source, severity, event_type, source_ip, q)
    cursor.execute(query, params)
    rows = [dict(row) for row in cursor.fetchall()]
    db.close()

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer)
    styles = getSampleStyleSheet()

    content = [Paragraph("Mini SIEM Logs Report", styles["Title"]), Spacer(1, 12)]

    for log in rows:
        text = (
            f"ID: {log.get('id', '-')}"
            f"<br/>Timestamp: {log.get('timestamp', '-')}"
            f"<br/>Source: {log.get('source', '-')}"
            f"<br/>Source IP: {log.get('source_ip', '-')}"
            f"<br/>Event Type: {log.get('event_type', '-')}"
            f"<br/>Severity: {log.get('severity', '-')}"
            f"<br/>User Label: {log.get('user_label', '-')}"
            f"<br/>Message Hash: {log.get('message_hash', '-')}"
            f"<br/>Message: {log.get('message', '-')}"
        )
        content.append(Paragraph(text, styles["Normal"]))
        content.append(Spacer(1, 10))

    doc.build(content)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=logs_report.pdf"}
    )


@router.get("/model-metrics")
def get_model_metrics(current_user: dict = Depends(require_role(["viewer", "analyst", "admin"]))):
    log_audit_event(current_user["sub"], "VIEW_MODEL_METRICS", "/logs/model-metrics")

    metrics = {
        "model_name": "Isolation Forest",
        "training_dataset": "UNSW-NB15",
        "test_dataset": "UNSW-NB15_4",
        "accuracy": 0.8462,
        "precision": 0.5680,
        "recall": 0.9956,
        "f1_score": 0.7234,
        "notes": "Current production model used in the AI-enhanced Mini SIEM."
    }

    return metrics


@router.post("/backup")
def backup_db(current_user: dict = Depends(require_role(["admin"]))):
    log_audit_event(current_user["sub"], "BACKUP_DB", "/logs/backup")

    backup_filename = f"backup_siem_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.db"
    shutil.copy("siem.db", backup_filename)

    return {
        "message": "Backup created successfully",
        "backup_file": backup_filename
    }


@router.post("/label")
def label_log(
    log_id: int = Query(...),
    label: str = Query(...),
    current_user: dict = Depends(require_role(["admin"]))
):
    log_audit_event(current_user["sub"], "LABEL_LOG", "/logs/label")

    db_gen = get_db()
    db = next(db_gen)
    cursor = db.cursor()

    cursor.execute("UPDATE logs SET user_label = ? WHERE id = ?", (label.upper(), log_id))
    db.commit()

    if cursor.rowcount == 0:
        db.close()
        raise HTTPException(status_code=404, detail="Log not found")

    db.close()
    return {
        "message": "Log labeled successfully",
        "log_id": log_id,
        "label": label.upper()
    }


# ... كل الكود عندك كما هو بدون تغيير ...

@router.get("/dashboard")
def dashboard(
    current_user: dict = Depends(require_role(["viewer", "analyst", "admin"]))
):
    log_audit_event(current_user["sub"], "VIEW_DASHBOARD", "/logs/dashboard")
    return FileResponse(Path("templates/dashboard.html"))
# ... باقي الكود كما هو ...

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
