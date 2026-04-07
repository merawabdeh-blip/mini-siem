from fastapi import FastAPI
from app.database import init_db
from app.routes.logs import router as logs_router

app = FastAPI(title="Mini SIEM")

init_db()
app.include_router(logs_router)

@app.get("/")
def root():
    return {"message": "Mini SIEM is running"}
