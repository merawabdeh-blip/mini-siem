from fastapi import FastAPI
from app.database import init_db
from app.routes.logs import router as logs_router
from app.utils.log_reader import read_logs

app = FastAPI(title="Mini SIEM")

# -------------------------
# Initialize Database
# -------------------------
init_db()

# -------------------------
# Include Routes
# -------------------------
app.include_router(logs_router)

# -------------------------
# Root Endpoint
# -------------------------
@app.get("/")
def root():
    return {"message": "Mini SIEM is running"}

# -------------------------
# Test Endpoint
# -------------------------
@app.get("/logs/alerts")
def test_alerts():
    return {"status": "working"}
