"""
Scans Router - API endpoints for vulnerability scanning operations.

This module provides endpoints for:
- Starting new vulnerability scans
- Checking scan status and progress
- Retrieving scan results and logs
- Listing all scans for a user

All endpoints require authentication via Bearer token.
"""

from fastapi import APIRouter, Request, HTTPException, Body
from pydantic import BaseModel, Field
from scanner.models import ScanTarget
from scanner.auth_manager import AuthenticationManager
from scanner.task_queue import add_job, get_job_status, get_job_result, get_job_progress
from db import database as db
from typing import List, Optional, Union, Dict
from urllib.parse import urlparse
import ipaddress
import socket
import requests
from scanner.task_queue import uuid_to_db_id
from db.database import get_connection, get_logs_for_scan, get_scans_for_user

router = APIRouter(tags=["scanner"])


class StartScanRequest(BaseModel):
    """Body schema for POST /scan/ — credentials must be in the body, never the URL."""

    url: str = Field(..., description="Target URL (http/https)")
    max_pages: int = Field(default=30, ge=1, le=500)
    target_login_url: Optional[str] = None
    target_username: Optional[str] = None
    target_password: Optional[str] = None
    proxy: Optional[str] = None
    enable_graph_analysis: bool = False


def _validate_target_url(url: str) -> str:
    """
    Reject URLs that would let the scanner reach internal/loopback/cloud-metadata
    endpoints (SSRF defense). Returns the validated URL or raises HTTPException(400).
    """
    if not url:
        raise HTTPException(status_code=400, detail="url is required")

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(
            status_code=400,
            detail="Only http:// and https:// URLs are allowed"
        )
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="URL has no hostname")

    host = parsed.hostname
    try:
        # Resolve all addresses to catch DNS-rebinding tricks at submit time.
        addresses = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        # Allow scanning of unresolved hosts (lab/CTF), but still block obvious local strings.
        addresses = set()
        if host.lower() in {"localhost", "metadata.google.internal"}:
            raise HTTPException(status_code=400, detail="Target host is not allowed")

    for addr in addresses:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            raise HTTPException(
                status_code=400,
                detail="Target resolves to a private or reserved address"
            )

    return url


def _validate_proxy(proxy: Optional[str]) -> Optional[str]:
    """Allow only http(s) proxies. Reject schemes like file:// gopher:// etc."""
    if not proxy:
        return None
    parsed = urlparse(proxy)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="proxy must be http:// or https://")
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="proxy URL has no hostname")
    return proxy


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
def start_scan(request: Request, payload: StartScanRequest = Body(...)):
    """
    Queue a new vulnerability scan.

    The request body carries the target URL, optional target-site credentials,
    and scan options. Credentials are never accepted as query-string parameters
    so they don't end up in access logs / browser history.

    Returns ``{job_id, status, message}``. Poll ``/scan/{job_id}/progress`` for
    real-time updates and ``/scan/{job_id}`` once status is ``completed``.

    Raises 400 on URL/proxy validation failure, 401 if unauthenticated.
    """
    # Step 0: Validate inputs early (SSRF defense)
    url = _validate_target_url(payload.url)
    proxy = _validate_proxy(payload.proxy)
    target_login_url = (
        _validate_target_url(payload.target_login_url)
        if payload.target_login_url else None
    )

    # Step 1: Handle target site authentication (if provided)
    cookies_to_pass = None
    if payload.target_username and payload.target_password and target_login_url:
        auth_manager = AuthenticationManager()
        login_session = auth_manager.login(
            target_login_url, payload.target_username, payload.target_password
        )
        if login_session:
            cookies_to_pass = requests.utils.dict_from_cookiejar(login_session.cookies)

    # Step 2: Verify the requesting user is authenticated
    current_user_id = request.state.user["user_id"] if request.state.user else None
    if not current_user_id:
        raise HTTPException(status_code=401, detail="User must be logged in to start a scan.")

    # Step 3: Queue the scan job for background processing
    job_id = add_job(
        url=url,
        max_pages=payload.max_pages,
        cookies=cookies_to_pass,
        user_id=current_user_id,
        proxy=proxy,
        enable_graph_analysis=payload.enable_graph_analysis,
    )

    return {
        "job_id": job_id,
        "status": "queued",
        "message": "Scan queued. Poll /scan/{job_id}/progress for real-time updates.",
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
    import logging as _logging
    _logger = _logging.getLogger("scans.router")

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
    except Exception:
        # Log the full exception server-side; never expose internal detail to clients.
        _logger.exception("Failed to retrieve logs for job %s (db_scan_id=%s)", job_id, db_scan_id)
        raise HTTPException(status_code=500, detail="Failed to retrieve scan logs")
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

@router.get("/{job_id}/graph")
def get_scan_graph(job_id: str, request: Request):
    """
    Get the DFS vulnerability graph analysis data for a scan.
    Returns JSON diagram data for frontend visualization.
    """
    db_scan_id = _authorize_job_access(job_id, request)
    conn = db.get_connection()
    try:
        graph_json = db.get_graph_data(conn, db_scan_id)
        if not graph_json:
            raise HTTPException(status_code=404, detail="No graph analysis data available for this scan")
        import json
        return json.loads(graph_json)
    finally:
        conn.close()

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
        # get_vulnerabilities_for_scan returns sqlite3.Row objects, which are
        # not JSON-serialisable by FastAPI's encoder. Convert each row to a
        # plain dict so the response serialises correctly.
        return {"vulnerabilities": [dict(v) for v in vulns] if vulns else []}
    finally:
        conn.close()