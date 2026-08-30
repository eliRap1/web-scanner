from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, EmailStr, field_validator
import logging
import re

logger = logging.getLogger(__name__)

import db.database as database
from fastapi import APIRouter
router = APIRouter()

# Standalone app — used by the auth-flow test suite which mounts only the
# registration router (so it can exercise registration without spinning up the
# full main app and its background workers).
app = FastAPI(title="Web Scanner - Auth (Registration)")


# ---------- Models ----------
class RegisterPayload(BaseModel):
    username: str
    email: EmailStr
    password: str
    confirm_password: str

    @field_validator("username")
    def username_not_empty(cls, v):
        v = v.strip()
        if len(v) < 3:
            raise ValueError("username must be at least 3 characters")
        if " " in v:
            raise ValueError("username must not contain spaces")
        return v

    @field_validator("password")
    def password_policy(cls, v):
        if len(v) < 8:
            raise ValueError("password must be at least 8 characters long")
        if not re.search(r"[A-Z]", v):
            raise ValueError("password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("password must contain at least one lowercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("password must contain at least one digit")
        if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", v):
            raise ValueError("password must contain at least one special character")
        return v

    @field_validator("confirm_password")
    def passwords_match(cls, v, info):
        pw = info.data.get("password")
        if pw and v != pw:
            raise ValueError("passwords do not match")
        return v


# ---------- Helpers ----------
def hash_password(password: str) -> str:
    """Hash password using the project's DB hashing utility."""
    return database.hash_password(password)

def is_email_taken(conn, email: str) -> bool:
    c = conn.cursor()
    r = c.execute("SELECT 1 FROM Users WHERE email = ? LIMIT 1", (email,)).fetchone()
    return bool(r)

def is_username_taken(conn, username: str) -> bool:
    c = conn.cursor()
    r = c.execute("SELECT 1 FROM Users WHERE username = ? LIMIT 1", (username,)).fetchone()
    return bool(r)


# ---------- Endpoint ----------
@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterPayload):
    """
    Register a new user.
    
    Password requirements:
    - At least 8 characters
    - One uppercase letter
    - One lowercase letter
    - One digit
    - One special character
    """
    conn = database.get_connection()
    try:
        # Check if username or email already exists
        if is_username_taken(conn, payload.username):
            raise HTTPException(status_code=400, detail="username already taken")
        if is_email_taken(conn, payload.email):
            raise HTTPException(status_code=400, detail="email already registered")

        # Hash password with bcrypt
        password_hash = hash_password(payload.password)
        # IMPORTANT: Insert directly to avoid double-hashing
        # Don't use database.create_user() as it will hash again
        user_id = database.create_user_with_hash(
            conn,
            username=payload.username,
            email=payload.email,
            password_hash=password_hash,
            role="user",
        )

        return {
            "status": "ok",
            "user_id": user_id,
            "message": "user created successfully"
        }

    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        logger.exception("Registration failed: %s", e)
        raise HTTPException(status_code=500, detail="Registration failed due to an internal error")
    finally:
        conn.close()


# Health check endpoint
@router.get("/health")
def health_check():
    """Check if the API is running"""
    return {"status": "ok", "service": "registration"}


# Mount the router on the standalone app declared above so it's testable in
# isolation. The full main app mounts the same router separately.
app.include_router(router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)