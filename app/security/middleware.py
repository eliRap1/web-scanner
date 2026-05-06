"""
Authentication Middleware Module

This module provides request-level authentication for the FastAPI application.
It intercepts all incoming requests and validates Bearer tokens against the
Sessions table in the database.

Public endpoints (login, register, docs) bypass authentication.
All other endpoints require a valid, non-expired session token.

Usage:
    app.middleware("http")(auth_middleware)
"""

from fastapi import Request
from fastapi.responses import JSONResponse
import db.database as database

# Endpoints that don't require authentication
# Note: Some endpoints (like /logout) handle their own token validation
PUBLIC_PATHS = {
    "/",              # Root/health check
    "/login",         # User login
    "/logout",        # User logout (handles own token validation)
    "/register",      # User registration
    "/verify",        # Token verification
    "/refresh",       # Token refresh (handles own token validation)
    "/health",        # Health check
    "/docs",          # Swagger UI
    "/openapi.json",  # OpenAPI schema
    "/redoc",         # ReDoc documentation
    "/favicon.ico",   # Browser favicon request
    "/meta.json",     # Frontend metadata file
}

# Prefixes for paths that don't require authentication.
# Reports view/download endpoints used to live here when the SPA passed the
# token via query string; they now require a normal Authorization header so the
# bearer token never lands in URLs / access logs / referer chains.
PUBLIC_PREFIXES = (
    "/docs",
    "/openapi",
    "/redoc",
)


async def auth_middleware(request: Request, call_next):
    """
    FastAPI middleware for authenticating requests.

    This middleware:
    1. Allows CORS preflight (OPTIONS) requests to pass through
    2. Allows public paths without authentication
    3. Validates Bearer token from Authorization header
    4. Attaches user info to request.state.user for authenticated requests
    5. Returns 401 Unauthorized for invalid/missing tokens

    Args:
        request: The incoming FastAPI Request object
        call_next: The next middleware/route handler to call

    Returns:
        Response: Either the route response or a 401 JSON error
    """
    # Allow CORS preflight requests (OPTIONS) to pass through
    # These are sent by browsers before the actual request
    if request.method == "OPTIONS":
        return await call_next(request)

    path = request.url.path

    # Allow public paths without authentication
    if path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES):
        # Initialize user state as None for public paths
        request.state.user = None
        return await call_next(request)

    # Check for Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return JSONResponse(
            status_code=401,
            content={"detail": "Missing Authorization header"}
        )

    # Validate Bearer token format
    if not auth_header.startswith("Bearer "):
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid Authorization format. Use: Bearer <token>"}
        )

    # Extract and validate token
    token = auth_header[7:].strip()

    if not token:
        return JSONResponse(
            status_code=401,
            content={"detail": "Empty token provided"}
        )

    # Validate token against database
    conn = database.get_connection()
    try:
        user = database.validate_session(conn, token)
        if not user:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or expired token"}
            )
        # Attach user info to request for use in route handlers
        request.state.user = user
    except Exception as e:
        # Log full error server-side; return generic message to client
        import logging
        logging.getLogger("auth.middleware").exception("Auth middleware failure")
        return JSONResponse(
            status_code=500,
            content={"detail": "Authentication service unavailable"}
        )
    finally:
        conn.close()

    return await call_next(request)
