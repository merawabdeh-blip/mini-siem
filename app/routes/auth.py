from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.auth import hash_password, verify_password, create_access_token
from app.database import get_db, insert_user, get_user_by_username

from fastapi import APIRouter, HTTPException, Depends
from app.dependencies import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "viewer"


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/register")
def register(user: RegisterRequest):
    db_gen = get_db()
    conn = next(db_gen)

    existing_user = get_user_by_username(conn, user.username)
    if existing_user:
        conn.close()
        raise HTTPException(status_code=400, detail="Username already exists")

    password_hash = hash_password(user.password)

    try:
        insert_user(conn, user.username, user.email, password_hash, user.role)
    except Exception:
        conn.close()
        raise HTTPException(status_code=400, detail="Username or email already exists")

    conn.close()
    return {"message": "User registered successfully"}


@router.post("/login")
def login(user: LoginRequest):
    db_gen = get_db()
    conn = next(db_gen)

    db_user = get_user_by_username(conn, user.username)
    if not db_user:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if not verify_password(user.password, db_user["password_hash"]):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token({
        "sub": db_user["username"],
        "role": db_user["role"]
    })

    conn.close()

    return {
        "access_token": token,
        "token_type": "bearer",
        "role": db_user["role"]
    }
@router.get("/me")
def me(current_user: dict = Depends(get_current_user)):
    return {
        "username": current_user.get("sub"),
        "role": current_user.get("role")
    }



