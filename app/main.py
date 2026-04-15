from fastapi import FastAPI
from app.database import init_db
from app.routes.logs import router as logs_router
from app.routes.auth import router as auth_router


app = FastAPI(title="Mini SIEM")

# -------------------------
# Initialize Database
# -------------------------
init_db()

# -------------------------
# Include Routes
# -------------------------
app.include_router(logs_router)
app.include_router(auth_router)

# -------------------------
# Root Endpoint
# -------------------------
@app.get("/")
def root():
    return {"message": "Mini SIEM is running"}

