from fastapi import APIRouter, Request, HTTPException
from ..scanner.models import ScanTarget
from ..scanner.auth_manager import AuthenticationManager
from ..scanner.task_queue import add_job, get_job_status, get_job_result, get_job_progress
from ..db import database as db
from typing import List, Optional, Union, Dict
import requests
from ..scanner.task_queue import uuid_to_db_id
from ..db.database import get_connection, get_logs_for_scan

router = APIRouter(tags=["scanner"])

@router.post("/")
def start_scan(
    request: Request,
    url: str,
    max_pages: int = 30,
    target_login_url: Optional[str] = None, 
    target_username: Optional[str] = None,
    target_password: Optional[str] = None
):
    # 1. Handle Auth (Target Site)
    cookies_to_pass = None
    if target_username and target_password and target_login_url:
        auth_manager = AuthenticationManager()
        login_session = auth_manager.login(target_login_url, target_username, target_password)
        
        if login_session:
            cookies_to_pass = requests.utils.dict_from_cookiejar(login_session.cookies)

    # 2. Get Logged-in User ID
    current_user_id = request.state.user["user_id"] if request.state.user else None
    
    if not current_user_id:
        raise HTTPException(status_code=401, detail="User must be logged in to start a scan.")

    # 3. Add to Queue
    job_id = add_job(
        url=url, 
        max_pages=max_pages, 
        cookies=cookies_to_pass,
        user_id=current_user_id
    )
    
    return {
        "job_id": job_id,
        "status": "queued",
        "message": "Scan queued. Please poll /scan/{job_id} for status."
    }

@router.get("/{job_id}", response_model=Union[List[ScanTarget], Dict[str, str]])
def get_scan_status(job_id: str, request: Request):
    _authorize_job_access(job_id, request)
    return get_job_result(job_id)

@router.get("/{job_id}/progress")
def get_scan_progress(job_id: str, request: Request):
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
