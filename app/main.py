from fastapi import FastAPI
from app.database import init_db
from app.routes.logs import router as logs_router

app = FastAPI(title="Mini SIEM")

# Initialize DB
init_db()

# Routes
app.include_router(logs_router)

# Root
@app.get("/")
def root():
    return {"message": "Mini SIEM is running"}

# Test endpoint
@app.get("/logs/alerts")
def test_alerts():
    return {"status": "working"}
