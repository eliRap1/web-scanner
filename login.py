from fastapi import FastAPI, HTTPException, status, Request
from pydantic import BaseModel
from typing import Optional
import sys

sys.path.append("D:/Users/Downloads/")
import database

app = FastAPI(title="Web Scanner - Auth (Login)")

# ---------- Models ----------

class LoginPayload(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    status: str
    token: str
    user_id: int
    username: str
    role: str
    message: str


class LogoutPayload(BaseModel):
    """
    Optional token in body.
    Normally the token is sent in Authorization header:
      Authorization: Bearer <token>
    This field is only a fallback for tools that can't set headers.
    """
    token: Optional[str] = None


class RefreshPayload(BaseModel):
    """
    Same idea as LogoutPayload:
    Prefer Authorization header, token in body is fallback only.
    """
    token: Optional[str] = None


class VerifyResponse(BaseModel):
    status: str
    valid: bool
    user_id: Optional[int] = None
    username: Optional[str] = None
    role: Optional[str] = None


# ---------- Helpers ----------

def extract_token_from_request(request: Request, body_token: Optional[str]) -> Optional[str]:
    """
    Priority:
    1. Authorization: Bearer <token>
    2. token from request body (body_token)
    """
    auth_header = request.headers.get("Authorization", "")
    token = None

    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()

    if not token and body_token:
        token = body_token.strip()

    return token


# ---------- Endpoints ----------

@app.post("/login", response_model=TokenResponse)
def login(payload: LoginPayload):
    """
    Authenticate user and return session token.

    Returns:
        - token: Session token to use in Authorization header
        - user_id: User's ID
        - username: User's username
        - role: User's role (user, security_officer, admin)
    """
    conn = database.get_connection()
    try:
        # Authenticate user
        user = database.authenticate_user(conn, payload.username, payload.password)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )

        # Create session token
        token = database.create_session(conn, user['user_id'], expires_in_hours=24)

        return TokenResponse(
            status="ok",
            token=token,
            user_id=user['user_id'],
            username=user['username'],
            role=user['role'],
            message="login successful"
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")
    finally:
        conn.close()


@app.post("/logout")
def logout(payload: LogoutPayload, request: Request):
    """
    Logout user by invalidating their session token.

    You can send the token in one of two ways:
    - Preferred:   Authorization: Bearer <token>
    - Fallback:    {"token": "<token>"} in request body
    """
    conn = database.get_connection()
    try:
        token = extract_token_from_request(request, payload.token)

        if not token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing token (send in Authorization header or body)"
            )

        # This will delete the session if it exists; if not, it's a no-op.
        database.delete_session(conn, token)

        return {"status": "ok", "message": "logged out successfully"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Logout failed: {str(e)}")
    finally:
        conn.close()


@app.post("/refresh", response_model=TokenResponse)
def refresh_token(payload: RefreshPayload, request: Request):
    """
    Refresh an existing valid token.

    Flow:
    1. Client sends current token (header or body).
    2. If token is valid & not expired → create a new token and extend expiry.
    3. Old token becomes invalid, client must store and use the new one.
    """
    conn = database.get_connection()
    try:
        token = extract_token_from_request(request, payload.token)

        if not token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing token (send in Authorization header or body)"
            )

        # Refresh session in DB
        new_token = database.refresh_session(conn, token)
        if not new_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token"
            )

        # Get user info for this (new) token
        session = database.validate_session(conn, new_token)
        if not session:
            # Should not normally happen if refresh_session succeeded
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to load user session after refresh"
            )

        return TokenResponse(
            status="ok",
            token=new_token,
            user_id=session["user_id"],
            username=session["username"],
            role=session["role"],
            message="token refreshed"
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token refresh failed: {str(e)}")
    finally:
        conn.close()


@app.get("/verify", response_model=VerifyResponse)
def verify_token(request: Request, token: Optional[str] = None):
    """Verify if a token is valid.

    Token can be sent in:
    - Preferred: Authorization: Bearer <token>
    - Backward-compat: query parameter /verify?token=<token>
    """
    extracted = extract_token_from_request(request, token)
    user = database.get_user_from_token(extracted) if extracted else None

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )

    return VerifyResponse(
        status="ok",
        valid=True,
        user_id=user["user_id"],
        username=user["username"],
        role=user["role"]
    )


@app.get("/health")
def health_check():
    """Check if the API is running"""
    return {"status": "ok", "service": "login"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
