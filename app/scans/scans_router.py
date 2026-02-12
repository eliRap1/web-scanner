"""
Scans Router - API endpoints for vulnerability scanning operations.

This module provides endpoints for:
- Starting new vulnerability scans
- Checking scan status and progress
- Retrieving scan results and logs
- Listing all scans for a user

All endpoints require authentication via Bearer token.
"""

from fastapi import APIRouter, Request, HTTPException
from scanner.models import ScanTarget
from scanner.auth_manager import AuthenticationManager
from scanner.task_queue import add_job, get_job_status, get_job_result, get_job_progress
from db import database as db
from typing import List, Optional, Union, Dict
import requests
from scanner.task_queue import uuid_to_db_id
from db.database import get_connection, get_logs_for_scan, get_scans_for_user

router = APIRouter(tags=["scanner"])


@router.get("/list")
def list_scans(request: Request):
    """
    List all scans for the current user.

    Returns a list of scan records with their status, target URL,
    start/end times, and findings count. Admins and security officers
    can see all scans; regular users only see their own.

    Returns:
        dict: Contains 'scans' list and 'stats' summary
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
        }

        return {
            "scans": scans,
            "stats": stats
        }
    finally:
        conn.close()


@router.post("/")
def start_scan(
    request: Request,
    url: str,
    max_pages: int = 30,
    target_login_url: Optional[str] = None,
    target_username: Optional[str] = None,
    target_password: Optional[str] = None,
    proxy: Optional[str] = None  # e.g., "http://127.0.0.1:8080" for Burp Suite
):
    """
    Start a new vulnerability scan.

    This endpoint queues a new scan job for the specified URL. The scan runs
    asynchronously in a background worker thread. Use the returned job_id to
    poll for status and results.

    Args:
        request: FastAPI request (contains authenticated user)
        url: Target URL to scan (must be a valid http/https URL)
        max_pages: Maximum number of pages to crawl (default: 30)
        target_login_url: Optional login URL for authenticated scanning
        target_username: Optional username for target site authentication
        target_password: Optional password for target site authentication

    Returns:
        dict: Contains job_id (UUID) for tracking, status, and message

    Raises:
        HTTPException 401: If user is not authenticated
    """
    # Step 1: Handle target site authentication (if provided)
    # This allows scanning authenticated areas of the target website
    cookies_to_pass = None
    if target_username and target_password and target_login_url:
        auth_manager = AuthenticationManager()
        login_session = auth_manager.login(target_login_url, target_username, target_password)

        if login_session:
            cookies_to_pass = requests.utils.dict_from_cookiejar(login_session.cookies)

    # Step 2: Verify the requesting user is authenticated
    current_user_id = request.state.user["user_id"] if request.state.user else None

    if not current_user_id:
        raise HTTPException(status_code=401, detail="User must be logged in to start a scan.")

    # Step 3: Queue the scan job for background processing
    job_id = add_job(
        url=url,
        max_pages=max_pages,
        cookies=cookies_to_pass,
        user_id=current_user_id,
        proxy=proxy  # Pass proxy for Burp/ZAP integration
    )

    return {
        "job_id": job_id,
        "status": "queued",
        "message": "Scan queued. Poll /scan/{job_id}/progress for real-time updates."
    }


@router.get("/{job_id}", response_model=Union[List[ScanTarget], Dict[str, str]])
def get_scan_status(job_id: str, request: Request):
    """
    Get the final results of a completed scan.

    Returns the full scan results including discovered targets and findings.
    For in-progress scans, use /scan/{job_id}/progress instead.

    Args:
        job_id: UUID of the scan job
        request: FastAPI request (for authentication)

    Returns:
        List[ScanTarget] or dict: Scan results or error message
    """
    _authorize_job_access(job_id, request)
    return get_job_result(job_id)


@router.get("/{job_id}/progress")
def get_scan_progress(job_id: str, request: Request):
    """
    Get real-time progress of an ongoing scan.

    Returns current crawl/test status including:
    - Current URL being processed
    - Number of pages visited
    - Number of targets/vulnerabilities found so far
    - Current phase (crawling, testing, completed)

    Poll this endpoint every 1-2 seconds during an active scan.

    Args:
        job_id: UUID of the scan job
        request: FastAPI request (for authentication)

    Returns:
        dict: Progress information including status, phase, and counts
    """
    _authorize_job_access(job_id, request)
    return get_job_progress(job_id)

@router.get("/{job_id}/logs")
def get_scan_logs(job_id: str, request: Request):
    """
    Returns logs for a specific scan job.
    """
    
    
    # 1. Get the DB scan_id from the UUID
    db_scan_id = uuid_to_db_id.get(job_id)
    
    if not db_scan_id:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # 2. Get current user
    current_user = request.state.user
    if not current_user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # 3. Fetch logs from database
    conn = get_connection()
    try:
        logs = get_logs_for_scan(
            conn, 
            db_scan_id, 
            current_user["user_id"], 
            current_user["role"]
        )
        return logs
    except PermissionError:
        raise HTTPException(status_code=403, detail="Access denied")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()
        
def _authorize_job_access(job_id: str, request: Request) -> int:
    """
    Returns db_scan_id if the current user is allowed to access this job.
    Raises HTTPException(404/403) otherwise.
    """
    current_user = getattr(request.state, "user", None)
    if not current_user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # uuid -> db scan id
    db_scan_id = uuid_to_db_id.get(job_id)
    if not db_scan_id:
        raise HTTPException(status_code=404, detail="Scan job not found")

    # Permission check via DB helper (owner/admin/security_officer)
    conn = db.get_connection()
    try:
        try:
            db.get_scan_by_id(
                conn,
                db_scan_id,
                current_user["user_id"],
                current_user["role"]
            )
        except PermissionError:
            raise HTTPException(status_code=403, detail="Forbidden")
    finally:
        conn.close()

    return db_scan_id

@router.get("/{job_id}/vulnerabilities")
def get_scan_vulnerabilities(job_id: str, request: Request):
    """Get all vulnerabilities found during a scan."""
    db_scan_id = _authorize_job_access(job_id, request)
    conn = db.get_connection()
    try:
        vulns = db.get_vulnerabilities_for_scan(
            conn, 
            db_scan_id, 
            request.state.user["user_id"],
            request.state.user["role"]
        )
        return {"vulnerabilities": vulns}
    finally:
        conn.close()