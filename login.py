from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
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


# ---------- Endpoint ----------
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
def logout(token: str):
    """
    Logout user by invalidating their session token.
    
    Pass token in request body: {"token": "your_token_here"}
    """
    conn = database.get_connection()
    try:
        database.delete_session(conn, token)
        return {"status": "ok", "message": "logged out successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Logout failed: {str(e)}")
    finally:
        conn.close()


@app.get("/verify")
def verify_token(token: str):
    """
    Verify if a token is valid.
    
    Pass token as query parameter: /verify?token=your_token_here
    """
    user = database.get_user_from_token(token)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    
    return {
        "status": "ok",
        "valid": True,
        "user_id": user['user_id'],
        "username": user['username'],
        "role": user['role']
    }


@app.get("/health")
def health_check():
    """Check if the API is running"""
    return {"status": "ok", "service": "login"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)