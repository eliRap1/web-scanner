"""
Reports Router - API endpoints for report generation and management.

This module provides endpoints for:
- Listing all reports for a user
- Generating HTML, PDF, and JSON reports from scan results
- Viewing reports inline (HTML)
- Downloading report files

Reports include:
- Executive summary with vulnerability statistics
- Visual charts showing severity distribution
- Detailed findings with evidence
- Remediation guidance with code examples
- Methodology explanation

All endpoints require authentication. View/download endpoints also accept
token as a query parameter to support opening reports in new browser tabs.
"""

from fastapi import APIRouter, HTTPException, Request, Query
from fastapi.responses import FileResponse, HTMLResponse
from pathlib import Path
from db import database as db
from reports.generator import ReportGenerator
from typing import Optional

router = APIRouter(prefix="/reports", tags=["reports"])
generator = ReportGenerator()


def get_user_from_request_or_token(request: Request, token: Optional[str] = None):
    """Backward-compat helper. Now defers entirely to middleware (no query token)."""
    return getattr(request.state, "user", None)


@router.get("/")
def list_reports(request: Request):
    """List all reports for the current user."""
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = db.get_connection()
    try:
        reports = db.get_reports_for_user(conn, user["user_id"], user["role"])
        return {"reports": [dict(r) for r in reports] if reports else []}
    finally:
        conn.close()


@router.get("/{report_id}")
def get_report(report_id: int, request: Request):
    """Get a specific report by ID."""
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = db.get_connection()
    try:
        report = db.get_report_by_id(conn, report_id, user["user_id"], user["role"])
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        return {"report": dict(report)}
    except PermissionError:
        raise HTTPException(status_code=403, detail="Access denied")
    finally:
        conn.close()


@router.post("/generate/{scan_id}")
def generate_report(
    scan_id: int,
    request: Request,
    format: str = Query(default="html", pattern="^(html|pdf|json)$")
):
    """Generate a report for a completed scan."""
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = db.get_connection()
    try:
        # Get scan data
        scan = db.get_scan_by_id(conn, scan_id, user["user_id"], user["role"])
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        scan_dict = dict(scan)

        if scan_dict.get("status") != "completed":
            raise HTTPException(status_code=400, detail="Scan not completed yet")

        # Get vulnerabilities
        vulns = db.get_vulnerabilities_for_scan(
            conn, scan_id, user["user_id"], user["role"]
        )
        vuln_list = vulns if vulns else []

        # Generate report file
        report_path = generator.generate_report(
            scan_id=scan_id,
            scan_data=scan_dict,
            vulnerabilities=vuln_list,
            format=format
        )

        # Create or update report record in database
        c = conn.cursor()

        # Check if report exists for this scan
        existing = c.execute(
            "SELECT report_id FROM Reports WHERE scan_id = ?",
            (scan_id,)
        ).fetchone()

        total_vulns = len(vuln_list)
        summary = f"Scan completed with {total_vulns} vulnerabilities found"

        if existing:
            # Update existing report
            c.execute(
                "UPDATE Reports SET report_path = ?, total_vulns = ?, summary = ? WHERE scan_id = ?",
                (report_path, total_vulns, summary, scan_id)
            )
            report_id = existing["report_id"]
        else:
            # Create new report record
            c.execute("""
                INSERT INTO Reports (user_id, scan_id, summary, total_vulns, report_path)
                VALUES (?, ?, ?, ?, ?)
            """, (user["user_id"], scan_id, summary, total_vulns, report_path))
            report_id = c.lastrowid

        conn.commit()

        return {
            "status": "ok",
            "report_id": report_id,
            "report_path": report_path,
            "format": format,
            "message": "Report generated successfully"
        }
    except PermissionError:
        raise HTTPException(status_code=403, detail="Access denied")
    finally:
        conn.close()


@router.get("/download/{report_id}")
def download_report(report_id: int, request: Request):
    """Download a generated report. Requires Authorization: Bearer <token>."""
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = db.get_connection()
    try:
        report = db.get_report_by_id(conn, report_id, user["user_id"], user["role"])
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        report_dict = dict(report)
        report_path = report_dict.get("report_path")

        if not report_path or not Path(report_path).exists():
            raise HTTPException(status_code=404, detail="Report file not found. Please generate the report first.")

        # Determine media type
        if report_path.endswith(".pdf"):
            media_type = "application/pdf"
        elif report_path.endswith(".json"):
            media_type = "application/json"
        else:
            media_type = "text/html"

        return FileResponse(
            path=report_path,
            media_type=media_type,
            filename=Path(report_path).name
        )
    except PermissionError:
        raise HTTPException(status_code=403, detail="Access denied")
    finally:
        conn.close()


@router.get("/view/{report_id}")
def view_report(report_id: int, request: Request):
    """View a report inline (HTML only). Requires Authorization: Bearer <token>."""
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = db.get_connection()
    try:
        report = db.get_report_by_id(conn, report_id, user["user_id"], user["role"])
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        report_dict = dict(report)
        report_path = report_dict.get("report_path")

        if not report_path or not Path(report_path).exists():
            raise HTTPException(status_code=404, detail="Report file not found")

        if not report_path.endswith(".html"):
            raise HTTPException(status_code=400, detail="Only HTML reports can be viewed inline")

        with open(report_path, "r", encoding="utf-8") as f:
            html_content = f.read()

        return HTMLResponse(content=html_content)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Access denied")
    finally:
        conn.close()
