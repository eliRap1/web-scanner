from fastapi import Request
from fastapi.responses import JSONResponse
import db.database as database
PUBLIC_PREFIXES = (
    "/login",
    "/register",
    "/verify",
    "/health",
    "/docs",
    "/openapi.json",
)
public_paths = [
    "/login",
    "/register",
    "/verify",
    "/health",
    "/docs",
    "/openapi.json",
]
async def auth_middleware(request: Request, call_next):
    path = request.url.path

    if path.startswith(PUBLIC_PREFIXES):
        return await call_next(request)

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return JSONResponse(
            status_code=401,
            content={"detail": "Missing Authorization header"}
        )

    if not auth_header.startswith("Bearer "):
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid Authorization format"}
        )

    token = auth_header[7:].strip()

    conn = database.get_connection()
    try:
        user = database.validate_session(conn, token)
        if not user:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or expired token"}
            )
        request.state.user = user
    finally:
        conn.close()

    return await call_next(request)
