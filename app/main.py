from fastapi import FastAPI
from fastapi.responses import FileResponse
from pathlib import Path

from app.database import init_db
from app.routes.logs import router as logs_router
from app.routes.auth import router as auth_router

app = FastAPI(title="AI-Enhanced Mini SIEM")

# =========================
# Initialize Database
# =========================
init_db()

# =========================
# Include Routers
# =========================
app.include_router(logs_router)
app.include_router(auth_router)

# =========================
# Login Page
# =========================
@app.get("/")
def login_page():
    return FileResponse(Path("templates/login.html"))

# =========================
# Register Page
# =========================
@app.get("/register")
def register_page():
    return FileResponse(Path("templates/register.html"))

# =========================
# Dashboard Page
# =========================
@app.get("/dashboard")
def dashboard_page():
    return FileResponse(Path("templates/dashboard.html"))

# =========================
# Health Check
# =========================
@app.get("/health")
def health():
    return {
        "status": "running",
        "system": "AI-Enhanced Mini SIEM"
    }
