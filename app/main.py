from fastapi import FastAPI
from app.database import init_db
from app.routes.logs import router as logs_router
from app.detection_engine import run_detection
app = FastAPI(title="Mini SIEM")

# Initialize database
init_db()



# Include routes
app.include_router(logs_router)

@app.get("/logs/alerts")
def get_alerts():
    return {"test": "NEW CODE WORKING"}

    # 🔥 دمج المصدرين
    all_logs = file_logs + logs_db

    alerts = run_detection(all_logs)
    return alerts
@app.get("/logs")
def get_logs():
    file_logs = read_logs("logs.txt")
    return file_logs + logs_db
