"""
Web Scanner API - Main Application Entry Point

This is the FastAPI application that provides:
- Authentication endpoints (login, register, token management)
- Vulnerability scanning endpoints (start scan, check status, get results)
- Report generation endpoints (generate, view, download reports)

The application uses SQLite for persistence and Playwright for browser automation.
"""

import os
from fastapi import FastAPI, Request, HTTPException
from contextlib import asynccontextmanager
from scanner.worker import start_worker
from security.middleware import auth_middleware
from api.auth.login import router as login_router
from api.auth.register import router as register_router
from scans.scans_router import router as scans_router
from reports.reports_router import router as reports_router
from db.database import init_database, ensure_admin_exists, get_connection, get_scans_for_user
from fastapi.middleware.cors import CORSMiddleware
from scanner.task_queue import recover_stuck_scans_on_startup
from db.backup import start_scheduler
import threading


def _allowed_origins() -> list[str]:
    """Read allowed CORS origins from env (comma-separated). Default = localhost dev."""
    raw = os.environ.get("ALLOWED_ORIGINS", "").strip()
    if raw:
        return [o.strip() for o in raw.split(",") if o.strip()]
    return ["http://localhost:5173", "http://127.0.0.1:5173"]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.

    Startup tasks:
    - Initialize database schema and run migrations
    - Ensure default admin user exists
    - Recover any scans stuck in 'running' state from previous crash
    - Start the background worker thread for processing scan jobs

    Shutdown tasks:
    - (None currently - workers are daemon threads)
    """
    init_database()
    ensure_admin_exists()
    recover_stuck_scans_on_startup()
    start_worker()
    backup_thread = threading.Thread(target=start_scheduler, daemon=True)
    backup_thread.start()
    yield


app = FastAPI(
    title="Web Scanner API",
    description="A comprehensive web vulnerability scanner with automated crawling and testing",
    version="1.0.0",
    lifespan=lifespan
)

# ---------- CORS Middleware (must be added BEFORE auth middleware) ----------
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Auth Middleware ----------
app.middleware("http")(auth_middleware)

# ---------- Routers ----------
app.include_router(login_router, tags=["Auth"])
app.include_router(register_router, tags=["Auth"])
app.include_router(scans_router, prefix="/scan", tags=["Scanner"])
app.include_router(reports_router, tags=["Reports"])


# ---------- Additional Endpoints ----------

@app.get("/")
def root():
    """
    Root endpoint - returns service status and links.

    Returns:
        dict: Service status, name, and documentation URL
    """
    return {
        "status": "ok",
        "service": "web-scanner",
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/scans")
def list_all_scans(request: Request):
    """
    List all scans for the current user (top-level endpoint).

    This endpoint provides scan listing at /scans for dashboard compatibility.
    Admins see all scans; regular users see only their own.

    Returns:
        list: Array of scan records with status, URL, timing, and findings
    """
    current_user = getattr(request.state, "user", None)
    if not current_user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = get_connection()
    try:
        scans = get_scans_for_user(conn, current_user["user_id"], current_user["role"])
        return scans
    finally:
        conn.close()


@app.get("/stats")
def get_dashboard_stats(request: Request):
    """
    Get dashboard statistics for the current user.

    Returns aggregated counts of scans by status and total vulnerabilities found.

    Returns:
        dict: Statistics including total, active, completed, failed counts
    """
    current_user = getattr(request.state, "user", None)
    if not current_user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = get_connection()
    try:
        scans = get_scans_for_user(conn, current_user["user_id"], current_user["role"])

        # Calculate statistics
        stats = {
            "total": len(scans),
            "active": sum(1 for s in scans if s.get("status") == "running"),
            "completed": sum(1 for s in scans if s.get("status") == "completed"),
            "failed": sum(1 for s in scans if s.get("status") == "failed"),
            "pending": sum(1 for s in scans if s.get("status") == "pending"),
            "total_findings": sum(s.get("findings_count", 0) or 0 for s in scans),
        }

        return stats
    finally:
        conn.close()
