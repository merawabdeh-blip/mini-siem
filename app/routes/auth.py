from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from app.auth import hash_password, verify_password, create_access_token
from app.database import get_db, insert_user, get_user_by_username
from app.dependencies import get_current_user
from app.audit import log_audit_event

router = APIRouter(prefix="/auth", tags=["Authentication"])

# =========================
# Simple Login Protection
# =========================
FAILED_LOGIN_ATTEMPTS = {}
MAX_FAILED_ATTEMPTS = 5


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

    try:
        existing_user = get_user_by_username(conn, user.username)

        if existing_user:
            raise HTTPException(status_code=400, detail="Username already exists")

        password_hash = hash_password(user.password)

        insert_user(
            conn,
            user.username,
            user.email,
            password_hash,
            user.role
        )

        log_audit_event(user.username, "REGISTER_SUCCESS", "/auth/register")

        return {
            "message": "User registered successfully"
        }

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Registration failed. Username or email may already exist."
        )

    finally:
        conn.close()


@router.post("/login")
def login(user: LoginRequest):
    db_gen = get_db()
    conn = next(db_gen)

    try:
        username = user.username

        if username not in FAILED_LOGIN_ATTEMPTS:
            FAILED_LOGIN_ATTEMPTS[username] = 0

        if FAILED_LOGIN_ATTEMPTS[username] >= MAX_FAILED_ATTEMPTS:
            log_audit_event(username, "ACCOUNT_LOCKED", "/auth/login")
            raise HTTPException(
                status_code=403,
                detail="Account locked due to too many failed login attempts"
            )

        db_user = get_user_by_username(conn, username)

        if not db_user:
            FAILED_LOGIN_ATTEMPTS[username] += 1
            log_audit_event(username, "LOGIN_FAILED_USER_NOT_FOUND", "/auth/login")
            raise HTTPException(
                status_code=401,
                detail="Invalid username or password"
            )

        if not verify_password(user.password, db_user["password_hash"]):
            FAILED_LOGIN_ATTEMPTS[username] += 1
            log_audit_event(username, "LOGIN_FAILED_WRONG_PASSWORD", "/auth/login")
            raise HTTPException(
                status_code=401,
                detail="Invalid username or password"
            )

        FAILED_LOGIN_ATTEMPTS[username] = 0

        token = create_access_token({
            "sub": db_user["username"],
            "role": db_user["role"]
        })

        log_audit_event(db_user["username"], "LOGIN_SUCCESS", "/auth/login")

        return {
            "access_token": token,
            "token_type": "bearer",
            "role": db_user["role"]
        }

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Login failed due to server error"
        )

    finally:
        conn.close()


@router.get("/me")
def me(current_user: dict = Depends(get_current_user)):
    return {
        "username": current_user.get("sub"),
        "role": current_user.get("role")
    }
