import sqlite3
from functools import wraps
import logging
from typing import Optional, Tuple, Dict, Any

DB_NAME = "web_scanner.db"
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("database")

def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def create_base_schema(conn):
    c = conn.cursor()

    # --- USERS ---
    c.execute("""
    CREATE TABLE IF NOT EXISTS Users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        role_level INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME
    );
    """)

    # --- SCANS ---
    c.execute("""
    CREATE TABLE IF NOT EXISTS Scans (
        scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        target_url TEXT NOT NULL,
        status TEXT CHECK(status IN ('pending','running','completed','failed')) DEFAULT 'pending',
        start_time DATETIME,
        end_time DATETIME,
        findings_count INTEGER DEFAULT 0,
        report_id INTEGER,
        notes TEXT,
        FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE,
        FOREIGN KEY (report_id) REFERENCES Reports(report_id) ON DELETE SET NULL
    );
    """)

    # --- FORMS ---
    c.execute("""
    CREATE TABLE IF NOT EXISTS Forms (
        form_id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        page_url TEXT NOT NULL,
        method TEXT CHECK(method IN ('GET','POST','PUT','DELETE')),
        action TEXT,
        inputs TEXT,
        FOREIGN KEY (scan_id) REFERENCES Scans(scan_id) ON DELETE CASCADE
    );
    """)

    # --- VULNERABILITIES ---
    c.execute("""
    CREATE TABLE IF NOT EXISTS Vulnerabilities (
        vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        form_id INTEGER,
        vuln_type TEXT NOT NULL,
        severity TEXT CHECK(severity IN ('low','medium','high','critical')) DEFAULT 'medium',
        description TEXT,
        payload_used TEXT,
        confirmed BOOLEAN DEFAULT 0,
        evidence TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES Scans(scan_id) ON DELETE CASCADE,
        FOREIGN KEY (form_id) REFERENCES Forms(form_id) ON DELETE SET NULL
    );
    """)

    # --- REPORTS ---
    c.execute("""
    CREATE TABLE IF NOT EXISTS Reports (
        report_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        scan_id INTEGER UNIQUE NOT NULL,
        summary TEXT,
        total_vulns INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        report_path TEXT,
        FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE,
        FOREIGN KEY (scan_id) REFERENCES Scans(scan_id) ON DELETE CASCADE
    );
    """)

    # --- LOGS ---
    c.execute("""
    CREATE TABLE IF NOT EXISTS Logs (
        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        level TEXT CHECK(level IN ('info','warning','error')) DEFAULT 'info',
        message TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES Scans(scan_id) ON DELETE CASCADE
    );
    """)

    conn.commit()

def apply_migrations(conn):
    c = conn.cursor()
    current_version = c.execute("PRAGMA user_version;").fetchone()[0]

    # v1 
    if current_version == 0:
        create_base_schema(conn)
        c.execute("PRAGMA user_version = 1;")
        current_version = 1
        logger.info("[MIGRATION] Initialized base schema -> version 1")

    # v2 
    if current_version < 2:
        # create_base_schema already added last_login and role_level above,
        # but keep this for safety if migrating from old schema without those fields.
        try:
            c.execute("ALTER TABLE Users ADD COLUMN last_login DATETIME;")
        except Exception:
            pass
        try:
            c.execute("ALTER TABLE Users ADD COLUMN role_level INTEGER DEFAULT 1;")
        except Exception:
            pass
        c.execute("PRAGMA user_version = 2;")
        current_version = 2
        logger.info("[MIGRATION] Upgraded schema -> version 2")

    conn.commit()
    logger.info(f"[MIGRATION] Current schema version: {current_version}")

def run_integrity_checks(conn):
    c = conn.cursor()
    problems = []

    integrity = c.execute("PRAGMA integrity_check;").fetchone()[0]
    if integrity != "ok":
        problems.append(f"PRAGMA integrity_check failed: {integrity}")

    fk_issues = c.execute("PRAGMA foreign_key_check;").fetchall()
    if fk_issues:
        problems.append(f"Foreign key violations: {fk_issues}")

    invalid_status = c.execute("""
        SELECT scan_id, status FROM Scans
        WHERE status NOT IN ('pending','running','completed','failed')
    """).fetchall()
    if invalid_status:
        problems.append(f"Invalid scan status values: {invalid_status}")

    invalid_severity = c.execute("""
        SELECT vuln_id, severity FROM Vulnerabilities
        WHERE severity NOT IN ('low','medium','high','critical')
    """).fetchall()
    if invalid_severity:
        problems.append(f"Invalid vulnerability severity values: {invalid_severity}")

    invalid_levels = c.execute("""
        SELECT log_id, level FROM Logs
        WHERE level NOT IN ('info','warning','error')
    """).fetchall()
    if invalid_levels:
        problems.append(f"Invalid log levels: {invalid_levels}")

    orphan_reports = c.execute("""
        SELECT r.report_id
        FROM Reports r
        LEFT JOIN Scans s ON r.scan_id = s.scan_id
        WHERE s.scan_id IS NULL;
    """).fetchall()
    if orphan_reports:
        problems.append(f"Orphan reports (no matching scan): {orphan_reports}")

    if not problems:
        logger.info("[INTEGRITY] All checks passed successfully.")
        return True
    else:
        logger.warning("[INTEGRITY] Problems found:")
        for p in problems:
            logger.warning("  - %s", p)
        return False

def init_database():
    conn = get_connection()
    try:
        apply_migrations(conn)
        run_integrity_checks(conn)
    finally:
        conn.close()

#Premistion Roles
ROLE_MAP = {
    "readonly": 0,
    "user": 1,
    "security_officer": 2,
    "admin": 3
}

PERMISSIONS = {
    "admin": ["read_all", "write_all", "delete", "create_scan", "view_reports", "manage_users"],
    "security_officer": ["read_all", "create_scan", "view_reports"],
    "user": ["create_scan", "view_own", "view_reports"],
    "readonly": ["read_all"]
}

def user_has_permission(role: str, action: str) -> bool:
    """
    בודק האם תפקיד מסוים מכיל את ההרשאה לפעולה נתונה.
    """
    if not role:
        return False
    if role not in PERMISSIONS:
        return False
    return action in PERMISSIONS[role]

def can_access_scan(user_role: str, user_id: int, scan_owner_id: int) -> bool:
    """
    בדיקה פשוטה אם המשתמש יכול לגשת לסריקה מסויימת.
    """
    if user_role in ("admin", "security_officer"):
        return True
    return user_id == scan_owner_id

def can_access_report(user_role: str, user_id: int, report_user_id: int) -> bool:
    if user_role in ("admin", "security_officer"):
        return True
    return user_id == report_user_id

# -------------------------------
# row level
# -------------------------------
def get_scans_for_user(conn, user_id: int, user_role: str):
    """
    מחזיר רשימת סריקות בהתאם להרשאות המשתמש.
    admin/security_officer = כל הסריקות
    user = רק סריקות שלו
    """
    c = conn.cursor()
    if user_role in ("admin", "security_officer"):
        rows = c.execute("SELECT * FROM Scans ORDER BY start_time DESC").fetchall()
    else:
        rows = c.execute("SELECT * FROM Scans WHERE user_id = ? ORDER BY start_time DESC", (user_id,)).fetchall()
    return [dict(r) for r in rows]

def get_scan_by_id(conn, scan_id: int, requesting_user_id: int, requesting_user_role: str):
    c = conn.cursor()
    row = c.execute("SELECT * FROM Scans WHERE scan_id = ?", (scan_id,)).fetchone()
    if not row:
        return None
    scan_owner_id = row["user_id"]
    if not can_access_scan(requesting_user_role, requesting_user_id, scan_owner_id):
        raise PermissionError("Access denied to scan")
    return dict(row)

def get_reports_for_user(conn, user_id: int, user_role: str):
    c = conn.cursor()
    if user_role in ("admin", "security_officer"):
        rows = c.execute("SELECT * FROM Reports ORDER BY created_at DESC").fetchall()
    else:
        rows = c.execute("SELECT * FROM Reports WHERE user_id = ? ORDER BY created_at DESC", (user_id,)).fetchall()
    return [dict(r) for r in rows]

def get_report_by_id(conn, report_id: int, requesting_user_id: int, requesting_user_role: str):
    c = conn.cursor()
    row = c.execute("SELECT * FROM Reports WHERE report_id = ?", (report_id,)).fetchone()
    if not row:
        return None
    if not can_access_report(requesting_user_role, requesting_user_id, row["user_id"]):
        raise PermissionError("Access denied to report")
    return dict(row)

def get_logs_for_scan(conn, scan_id: int, requesting_user_id: int, requesting_user_role: str):
    # בדוק תחילה גישה לסריקה
    scan = get_scan_by_id(conn, scan_id, requesting_user_id, requesting_user_role)
    if not scan:
        raise ValueError("Scan not found")
    c = conn.cursor()
    rows = c.execute("SELECT * FROM Logs WHERE scan_id = ? ORDER BY created_at ASC", (scan_id,)).fetchall()
    return [dict(r) for r in rows]

# -------------------------------
# mangment Role / Utilities
# -------------------------------
def set_user_role(conn, user_id: int, role: str):
    if role not in ROLE_MAP:
        raise ValueError("Unknown role")
    c = conn.cursor()
    c.execute("UPDATE Users SET role = ?, role_level = ? WHERE user_id = ?", (role, ROLE_MAP[role], user_id))
    conn.commit()
    logger.info("Set user %s role -> %s", user_id, role)

def create_user(conn, username: str, email: str, password_hash: str, role: str = "user"):
    c = conn.cursor()
    c.execute("""
        INSERT INTO Users (username, email, password_hash, role, role_level)
        VALUES (?, ?, ?, ?, ?)
    """, (username, email, password_hash, role, ROLE_MAP.get(role, 1)))
    conn.commit()
    return c.lastrowid

def get_user_by_id(conn, user_id: int) -> Optional[Dict[str, Any]]:
    c = conn.cursor()
    r = c.execute("SELECT user_id, username, email, role, role_level, created_at, last_login FROM Users WHERE user_id = ?", (user_id,)).fetchone()
    return dict(r) if r else None

def get_user_by_username(conn, username: str) -> Optional[Dict[str, Any]]:
    c = conn.cursor()
    r = c.execute("SELECT * FROM Users WHERE username = ?", (username,)).fetchone()
    return dict(r) if r else None

# ---------------------------------------
# api
# ---------------------------------------

# ---------- Helper
def get_user_from_token(token: str) -> Optional[Dict[str, Any]]:
    """
    STUB: החלף את המימוש לפי השיטה שלך (JWT validation וכו').
    הפונקציה מחזירה dict עם user_id ו-role לפחות:
        {"user_id": 1, "username": "alice", "role": "admin"}
    """
    # --- דוגמא סטאטית לשימוש מקומי בלבד ---
    # אם הטוקן == "admin-token" נחזיר admin; אם "user-token" נחזיר user וכו'.
    # החלף למימוש אמיתי עם JWT או DB lookup ב־sessions.
    if not token:
        return None
    if token == "admin-token":
        return {"user_id": 1, "username": "admin", "role": "admin"}
    if token == "sec-token":
        return {"user_id": 2, "username": "secuser", "role": "security_officer"}
    if token == "user-token":
        return {"user_id": 3, "username": "regular", "role": "user"}
    return None

# ---------- Flask-style decorator ----------
def requires_role(min_role: str):
    """
    דקורטור לשימוש בפונקציות/handlers בסגנון Flask.
    min_role יכול להיות 'user','security_officer','admin' - המשתמש חייב להיות בעל רמת role_level >= של min_role.
    דוגמה:
        @requires_role("security_officer")
        def admin_only_route(...):
            ...
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # מנסה לקרוא Authorization header (Bearer token)
            try:
                from flask import request, abort
            except Exception:
                logger.debug("Flask not installed or not in request context")
                raise RuntimeError("Flask context not available for requires_role decorator")

            auth = request.headers.get("Authorization", "")
            token = None
            if auth.startswith("Bearer "):
                token = auth.split(" ", 1)[1]
            user = get_user_from_token(token)
            if not user:
                abort(401, description="Unauthorized")

            user_role = user.get("role")
            # השוואת רמות
            if ROLE_MAP.get(user_role, 0) < ROLE_MAP.get(min_role, 0):
                abort(403, description="Forbidden - insufficient role")
            # מוסיפים את המשתמש ל־kwargs למקרה שהפונקציה צריכה אותו
            kwargs["_current_user"] = user
            return func(*args, **kwargs)
        return wrapper
    return decorator

# ---------- Flask-style requires_permission ----------
def requires_permission(permission: str):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                from flask import request, abort
            except Exception:
                raise RuntimeError("Flask context not available")
            auth = request.headers.get("Authorization", "")
            token = None
            if auth.startswith("Bearer "):
                token = auth.split(" ", 1)[1]
            user = get_user_from_token(token)
            if not user:
                abort(401, description="Unauthorized")
            if not user_has_permission(user.get("role"), permission):
                abort(403, description="Forbidden - missing permission")
            kwargs["_current_user"] = user
            return func(*args, **kwargs)
        return wrapper
    return decorator

# ---------- FastAPI dependency injection ----------
def fastapi_requires_role(min_role: str):
    """
    שימוש ב-FastAPI:
        @app.get("/admin")
        async def admin_endpoint(current_user=Depends(fastapi_requires_role("admin"))):
            # current_user בידיים שלך
    """
    from fastapi import Depends, HTTPException, status, Request

    async def dependency(request: Request):
        auth = request.headers.get("Authorization", "")
        token = None
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1]
        user = get_user_from_token(token)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
        if ROLE_MAP.get(user.get("role"), 0) < ROLE_MAP.get(min_role, 0):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        return user
    return Depends(dependency)

def fastapi_requires_permission(permission: str):
    from fastapi import Depends, HTTPException, status, Request
    async def dependency(request: Request):
        auth = request.headers.get("Authorization", "")
        token = None
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1]
        user = get_user_from_token(token)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
        if not user_has_permission(user.get("role"), permission):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        return user
    return Depends(dependency)

# ---------------------------------------
# דוגמאות שימוש (Flask / FastAPI)
# ---------------------------------------
# Flask:
# from flask import Flask, jsonify
# app = Flask(_name_)
#
# @app.route('/scans')
# @requires_role('user')   # לפחות user
# def scans_endpoint(_current_user=None):
#     conn = get_connection()
#     data = get_scans_for_user(conn, _current_user['user_id'], _current_user['role'])
#     conn.close()
#     return jsonify(data)
#
# FastAPI:
# from fastapi import FastAPI, Depends
# app = FastAPI()
#
# @app.get("/scans")
# async def scans_endpoint(current_user=fastapi_requires_role('user')):
#     conn = get_connection()
#     data = get_scans_for_user(conn, current_user['user_id'], current_user['role'])
#     conn.close()
#     return data

# ---------------------------------------
# פונקציות בדיקה/עזרה להטמעה
# ---------------------------------------
def ensure_admin_exists():
    """
    יוצר משתמש דיפולטיבי admin אם אין אחד כזה במסד (לנוחות פיתוח).
    אל תשתמש בזה בפרודקשן ללא החלפה של הסיסמא!
    """
    conn = get_connection()
    try:
        c = conn.cursor()
        r = c.execute("SELECT user_id FROM Users WHERE role = 'admin' LIMIT 1").fetchone()
        if r:
            logger.debug("Admin already exists")
            return
        #just an example
        create_user(conn, username="admin", email="admin@example.com", password_hash="changeme", role="admin")
        logger.info("Created default admin user (username=admin)")
    finally:
        conn.close()


if __name__ == "__main__":
    init_database()
    ensure_admin_exists()
    logger.info("Database ready.")