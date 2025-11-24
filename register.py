from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, EmailStr, field_validator
from passlib.context import CryptContext
import re
import sys

# מאפשר לייבא את database.py שלך
sys.path.append("D:/Users/Downloads/")
import database

app = FastAPI(title="Web Scanner - Auth (Registration)")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

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
    return pwd_context.hash(password)

def is_email_taken(conn, email: str) -> bool:
    c = conn.cursor()
    r = c.execute("SELECT 1 FROM Users WHERE email = ? LIMIT 1", (email,)).fetchone()
    return bool(r)

def is_username_taken(conn, username: str) -> bool:
    c = conn.cursor()
    r = c.execute("SELECT 1 FROM Users WHERE username = ? LIMIT 1", (username,)).fetchone()
    return bool(r)


# ---------- Endpoint ----------
@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterPayload):
    conn = database.get_connection()
    try:
        if is_username_taken(conn, payload.username):
            raise HTTPException(status_code=400, detail="username already taken")
        if is_email_taken(conn, payload.email):
            raise HTTPException(status_code=400, detail="email already registered")

        password_hash = hash_password(payload.password)
        user_id = database.create_user(
            conn,
            username=payload.username,
            email=payload.email,
            password_hash=password_hash,
            role="user"
        )

        return {"status": "ok", "user_id": user_id, "message": "user created successfully"}

    finally:
        conn.close()
