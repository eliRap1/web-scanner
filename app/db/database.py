import sqlite3
from functools import wraps
import logging
from typing import Optional, Tuple, Dict, Any
import os

try:
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
except ImportError as exc:  # pragma: no cover - hard requirement at runtime
    raise RuntimeError(
        "passlib[bcrypt] is required for password hashing. "
        "Install with: pip install 'passlib[bcrypt]'"
    ) from exc

# Allow overriding DB path for tests / different environments
# Example: WEB_SCANNER_DB=/tmp/test.db
DB_NAME = os.environ.get("WEB_SCANNER_DB", "web_scanner.db")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("database")

def get_connection():
    # check_same_thread=False makes it safer for FastAPI TestClient usage
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
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
        notes TEXT,
        FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE
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

    # --- SESSIONS (for token management) ---
    c.execute("""
    CREATE TABLE IF NOT EXISTS Sessions (
        session_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NOT NULL,
        FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE
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

    # v3 - Add Sessions table if needed
    if current_version < 3:
        try:
            c.execute("""
            CREATE TABLE IF NOT EXISTS Sessions (
                session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE
            );
            """)
        except Exception as e:
            logger.warning(f"Sessions table may already exist: {e}")
        c.execute("PRAGMA user_version = 3;")
        current_version = 3
        logger.info("[MIGRATION] Upgraded schema -> version 3")

    # v4 - Add url and parameter columns to Vulnerabilities table
    if current_version < 4:
        try:
            c.execute("ALTER TABLE Vulnerabilities ADD COLUMN url TEXT;")
        except Exception:
            pass  # Column may already exist
        try:
            c.execute("ALTER TABLE Vulnerabilities ADD COLUMN parameter TEXT;")
        except Exception:
            pass  # Column may already exist
        try:
            c.execute("ALTER TABLE Vulnerabilities ADD COLUMN confidence REAL DEFAULT 0.0;")
        except Exception:
            pass  # Column may already exist
        c.execute("PRAGMA user_version = 4;")
        current_version = 4
        logger.info("[MIGRATION] Upgraded schema -> version 4 (added url, parameter, confidence to Vulnerabilities)")

    # v5 - Add graph_data column to Scans for DFS graph analysis results
    if current_version < 5:
        try:
            c.execute("ALTER TABLE Scans ADD COLUMN graph_data TEXT;")
        except Exception:
            pass  # Column may already exist
        c.execute("PRAGMA user_version = 5;")
        current_version = 5
        logger.info("[MIGRATION] Upgraded schema -> version 5 (added graph_data to Scans)")

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
    """Initialize database with proper error handling and logging"""
    logger.info(f"Initializing database: {DB_NAME}")
    logger.info(f"Current directory: {os.getcwd()}")
    logger.info("Using password hashing: bcrypt")
    
    try:
        conn = get_connection()
        logger.info("Database connection established")
        
        try:
            apply_migrations(conn)
            logger.info("Migrations completed successfully")
            
            run_integrity_checks(conn)
            logger.info("Integrity checks completed")
            
        except Exception as e:
            logger.error(f"Error during initialization: {e}")
            import traceback
            traceback.print_exc()
            raise
        finally:
            conn.close()
            logger.info("Database connection closed")
            
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

# Permission Roles
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
    """Check if a given role includes permission for a specific action."""
    if not role:
        return False
    if role not in PERMISSIONS:
        return False
    return action in PERMISSIONS[role]

def can_access_scan(user_role: str, user_id: int, scan_owner_id: int) -> bool:
    """Check if user can access a specific scan."""
    if user_role in ("admin", "security_officer"):
        return True
    return user_id == scan_owner_id

def can_access_report(user_role: str, user_id: int, report_user_id: int) -> bool:
    """Check if user can access a specific report."""
    if user_role in ("admin", "security_officer"):
        return True
    return user_id == report_user_id

# -------------------------------
# Password Hashing Utilities
# -------------------------------
def hash_password(password: str) -> str:
    """Hash a password with bcrypt."""
    return pwd_context.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against its bcrypt hash."""
    try:
        return pwd_context.verify(password, stored_hash)
    except Exception:
        logger.exception("Password verification error")
        return False

# -------------------------------
# Session Management
# -------------------------------
def create_session(conn, user_id: int, expires_in_hours: int = 24) -> str:
    """Create a new session token for a user."""
    from datetime import datetime, timedelta
    import secrets
    
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(hours=expires_in_hours)
    
    c = conn.cursor()
    c.execute("""
        INSERT INTO Sessions (user_id, token, expires_at)
        VALUES (?, ?, ?)
    """, (user_id, token, expires_at))
    conn.commit()
    return token

def validate_session(conn, token: str) -> Optional[Dict[str, Any]]:
    """Validate a session token and return user info if valid."""
    from datetime import datetime
    
    c = conn.cursor()
    row = c.execute("""
        SELECT s.user_id, u.username, u.role, u.role_level, s.expires_at
        FROM Sessions s
        JOIN Users u ON s.user_id = u.user_id
        WHERE s.token = ?
    """, (token,)).fetchone()
    
    if not row:
        return None
    
    def _parse_dt(value):
        """Parse sqlite datetime column into a Python datetime."""
        if value is None:
            return None
        if hasattr(value, "year") and hasattr(value, "month"):
            return value  # already datetime
        # sqlite often returns 'YYYY-MM-DD HH:MM:SS[.ffffff]'
        try:
            return datetime.fromisoformat(str(value))
        except Exception:
            from datetime import datetime as _dt
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
                try:
                    return _dt.strptime(str(value), fmt)
                except Exception:
                    pass
            raise

    # Check if expired
    expires_at = _parse_dt(row['expires_at'])
    if expires_at and expires_at < datetime.now():
        # Delete expired session
        c.execute("DELETE FROM Sessions WHERE token = ?", (token,))
        conn.commit()
        return None
    
    return {
        "user_id": row['user_id'],
        "username": row['username'],
        "role": row['role'],
        "role_level": row['role_level']
    }

def delete_session(conn, token: str):
    """Delete a session (logout)."""
    c = conn.cursor()
    c.execute("DELETE FROM Sessions WHERE token = ?", (token,))
    conn.commit()

def rotate_session(conn, old_token: str, expires_in_hours: int = 24) -> Optional[str]:
    """Rotate an existing valid token into a new token (simple refresh)."""
    user = validate_session(conn, old_token)
    if not user:
        return None
    # Invalidate old and create new
    delete_session(conn, old_token)
    return create_session(conn, user["user_id"], expires_in_hours=expires_in_hours)

def refresh_session(conn, token: str, expires_in_hours: int = 24) -> Optional[str]:
    """
    Refresh an existing session token.

    Behavior:
    - If token is valid & not expired → rotate token (new random token) and extend its expiry.
    - If token is invalid or expired → return None.
    """
    from datetime import datetime, timedelta
    import secrets

    c = conn.cursor()
    row = c.execute(
        "SELECT session_id, user_id, expires_at FROM Sessions WHERE token = ?",
        (token,)
    ).fetchone()

    if not row:
        return None

    expires_at_raw = row["expires_at"]
    try:
        expires_at = datetime.fromisoformat(str(expires_at_raw))
    except Exception:
        from datetime import datetime as _dt
        expires_at = _dt.strptime(str(expires_at_raw), "%Y-%m-%d %H:%M:%S")

    # If session already expired – remove it and return None
    if expires_at < datetime.now():
        c.execute("DELETE FROM Sessions WHERE token = ?", (token,))
        conn.commit()
        return None

    # Rotate token + extend expiry
    new_token = secrets.token_urlsafe(32)
    new_expires = datetime.now() + timedelta(hours=expires_in_hours)

    c.execute(
        "UPDATE Sessions SET token = ?, expires_at = ? WHERE session_id = ?",
        (new_token, new_expires, row["session_id"])
    )
    conn.commit()
    return new_token


# -------------------------------
# Row Level Access Functions
# -------------------------------
def get_scans_for_user(conn, user_id: int, user_role: str):
    """Return list of scans based on user permissions."""
    c = conn.cursor()
    if user_role in ("admin", "security_officer"):
        rows = c.execute("SELECT * FROM Scans ORDER BY start_time DESC").fetchall()
    else:
        rows = c.execute("SELECT * FROM Scans WHERE user_id = ? ORDER BY start_time DESC", (user_id,)).fetchall()
    return [dict(r) for r in rows]

def get_scan_by_id(conn, scan_id: int, requesting_user_id: int, requesting_user_role: str):
    """Get a specific scan by ID with permission check."""
    c = conn.cursor()
    row = c.execute("SELECT * FROM Scans WHERE scan_id = ?", (scan_id,)).fetchone()
    if not row:
        return None
    scan_owner_id = row["user_id"]
    if not can_access_scan(requesting_user_role, requesting_user_id, scan_owner_id):
        raise PermissionError("Access denied to scan")
    return dict(row)

def get_reports_for_user(conn, user_id: int, user_role: str):
    """Return list of reports based on user permissions."""
    c = conn.cursor()
    if user_role in ("admin", "security_officer"):
        rows = c.execute("SELECT * FROM Reports ORDER BY created_at DESC").fetchall()
    else:
        rows = c.execute("SELECT * FROM Reports WHERE user_id = ? ORDER BY created_at DESC", (user_id,)).fetchall()
    return [dict(r) for r in rows]

def get_report_by_id(conn, report_id: int, requesting_user_id: int, requesting_user_role: str):
    """Get a specific report by ID with permission check."""
    c = conn.cursor()
    row = c.execute("SELECT * FROM Reports WHERE report_id = ?", (report_id,)).fetchone()
    if not row:
        return None
    if not can_access_report(requesting_user_role, requesting_user_id, row["user_id"]):
        raise PermissionError("Access denied to report")
    return dict(row)

def get_logs_for_scan(conn, scan_id: int, requesting_user_id: int, requesting_user_role: str):
    """Get logs for a specific scan with permission check."""
    scan = get_scan_by_id(conn, scan_id, requesting_user_id, requesting_user_role)
    if not scan:
        raise ValueError("Scan not found")
    c = conn.cursor()
    rows = c.execute("SELECT * FROM Logs WHERE scan_id = ? ORDER BY created_at ASC", (scan_id,)).fetchall()
    return [dict(r) for r in rows]

# -------------------------------
# Role Management / Utilities
# -------------------------------
def set_user_role(conn, user_id: int, role: str):
    """Set a user's role."""
    if role not in ROLE_MAP:
        raise ValueError("Unknown role")
    c = conn.cursor()
    c.execute("UPDATE Users SET role = ?, role_level = ? WHERE user_id = ?", (role, ROLE_MAP[role], user_id))
    conn.commit()
    logger.info("Set user %s role -> %s", user_id, role)

def create_user(conn, username: str, email: str, password: str, role: str = "user"):
    """
    Create a new user with hashed password.
    NOTE: This function hashes the password. If you're passing an already-hashed password,
    use create_user_with_hash() instead.
    """
    c = conn.cursor()
    password_hash = hash_password(password)
    c.execute("""
        INSERT INTO Users (username, email, password_hash, role, role_level)
        VALUES (?, ?, ?, ?, ?)
    """, (username, email, password_hash, role, ROLE_MAP.get(role, 1)))
    conn.commit()
    return c.lastrowid

def create_user_with_hash(conn, username: str, email: str, password_hash: str, role: str = "user"):
    """
    Create a new user with an already-hashed password.
    Use this when the password has already been hashed (e.g., in registration endpoint).
    """
    c = conn.cursor()
    c.execute("""
        INSERT INTO Users (username, email, password_hash, role, role_level)
        VALUES (?, ?, ?, ?, ?)
    """, (username, email, password_hash, role, ROLE_MAP.get(role, 1)))
    conn.commit()
    return c.lastrowid

def authenticate_user(conn, username: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticate a user by username and password."""
    user = get_user_by_username(conn, username)
    if not user:
        return None
    
    if not verify_password(password, user['password_hash']):
        return None
    
    # Update last login
    c = conn.cursor()
    c.execute("UPDATE Users SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?", (user['user_id'],))
    conn.commit()
    
    return {
        "user_id": user['user_id'],
        "username": user['username'],
        "email": user['email'],
        "role": user['role'],
        "role_level": user['role_level']
    }

def get_user_by_id(conn, user_id: int) -> Optional[Dict[str, Any]]:
    """Get user by ID (without password hash)."""
    c = conn.cursor()
    r = c.execute("SELECT user_id, username, email, role, role_level, created_at, last_login FROM Users WHERE user_id = ?", (user_id,)).fetchone()
    return dict(r) if r else None

def get_user_by_username(conn, username: str) -> Optional[Dict[str, Any]]:
    """Get user by username (includes password hash for authentication)."""
    c = conn.cursor()
    r = c.execute("SELECT * FROM Users WHERE username = ?", (username,)).fetchone()
    return dict(r) if r else None

# ---------------------------------------
# API Authentication Helper
# ---------------------------------------
def get_user_from_token(token: str) -> Optional[Dict[str, Any]]:
    """Validate token and return user info."""
    if not token:
        return None
    
    conn = get_connection()
    try:
        return validate_session(conn, token)
    finally:
        conn.close()

# ---------- Flask-style decorator ----------
# TODO: requires_role and requires_permission below are dead code — the project
# uses FastAPI, not Flask, and Flask is not in requirements.txt.  These decorators
# import Flask at call time and would raise RuntimeError on any invocation.
# Remove them together with requires_permission() in a future cleanup pass;
# the FastAPI equivalents (fastapi_requires_role / fastapi_requires_permission)
# already exist below.
def requires_role(min_role: str):
    """Decorator for Flask routes requiring minimum role level."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                from flask import request, abort
            except ImportError:
                raise RuntimeError("Flask not installed. Install with: pip install flask")

            auth = request.headers.get("Authorization", "")
            token = None
            if auth.startswith("Bearer "):
                token = auth.split(" ", 1)[1]
            
            user = get_user_from_token(token)
            if not user:
                abort(401, description="Unauthorized")

            user_role = user.get("role")
            if ROLE_MAP.get(user_role, 0) < ROLE_MAP.get(min_role, 0):
                abort(403, description="Forbidden - insufficient role")
            
            kwargs["_current_user"] = user
            return func(*args, **kwargs)
        return wrapper
    return decorator

def requires_permission(permission: str):
    """Decorator for Flask routes requiring specific permission."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                from flask import request, abort
            except ImportError:
                raise RuntimeError("Flask not installed")
            
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
    """FastAPI dependency for role-based access control."""
    try:
        from fastapi import Depends, HTTPException, status, Request
    except ImportError:
        raise RuntimeError("FastAPI not installed. Install with: pip install fastapi")

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
    """FastAPI dependency for permission-based access control."""
    try:
        from fastapi import Depends, HTTPException, status, Request
    except ImportError:
        raise RuntimeError("FastAPI not installed")
    
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
# Utility Functions
# ---------------------------------------
DEFAULT_ADMIN_USERNAME = os.environ.get("WEB_SCANNER_ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_EMAIL = os.environ.get("WEB_SCANNER_ADMIN_EMAIL", "admin@example.com")


def ensure_admin_exists():
    """
    Create the default admin user on first start if one does not exist.

    The admin password MUST be supplied via the WEB_SCANNER_ADMIN_PASSWORD
    environment variable. To boot a throwaway dev instance without setting one,
    set WEB_SCANNER_DEV=1 explicitly — the dev fallback is never used in
    production and prints a loud warning.
    """
    logger.info("Checking for admin user...")
    conn = get_connection()
    try:
        c = conn.cursor()
        r = c.execute("SELECT user_id FROM Users WHERE role = 'admin' LIMIT 1").fetchone()
        if r:
            logger.info(f"Admin user already exists (ID: {r[0]})")
            return

        admin_password = os.environ.get("WEB_SCANNER_ADMIN_PASSWORD")
        if not admin_password:
            if os.environ.get("WEB_SCANNER_DEV") == "1":
                admin_password = "Admin@123"
                logger.warning(
                    "WEB_SCANNER_DEV=1 set: bootstrapping with insecure default admin password. "
                    "DO NOT USE IN PRODUCTION."
                )
            else:
                raise RuntimeError(
                    "No admin user exists and WEB_SCANNER_ADMIN_PASSWORD is not set. "
                    "Set the env var (recommended) or pass WEB_SCANNER_DEV=1 to use the "
                    "insecure dev default."
                )

        logger.info("Creating admin user from environment configuration...")
        user_id = create_user(
            conn,
            username=DEFAULT_ADMIN_USERNAME,
            email=DEFAULT_ADMIN_EMAIL,
            password=admin_password,
            role="admin",
        )
        logger.info(f"Created admin user (ID: {user_id}, username={DEFAULT_ADMIN_USERNAME})")
    except Exception:
        logger.exception("Error ensuring admin exists")
        raise
    finally:
        conn.close()
# ... existing imports ...

# -------------------------------
# Logging & Anomaly Helpers
# -------------------------------

def insert_log(conn, scan_id: int, level: str, message: str):
    """
    Inserts a log entry into the Logs table.
    Levels: 'info', 'warning', 'error'.
    """
    c = conn.cursor()
    c.execute(
        "INSERT INTO Logs (scan_id, level, message, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
        (scan_id, level, message)
    )
    conn.commit()

def get_scan_logs(conn, scan_id: int):
    """
    Retrieves all logs for a specific scan, ordered by time.
    """
    c = conn.cursor()
    rows = c.execute(
        "SELECT * FROM Logs WHERE scan_id = ? ORDER BY created_at ASC",
        (scan_id,)
    ).fetchall()
    return [dict(r) for r in rows]

def insert_vulnerability(conn, scan_id, url, param, vuln_type, payload, severity, confidence=0.8):
    """Insert a vulnerability finding into database."""
    c = conn.cursor()
    c.execute("""
        INSERT INTO Vulnerabilities (
            scan_id, vuln_type, severity,
            payload_used, description, confirmed, evidence,
            url, parameter, confidence
        )
        VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
    """, (
        scan_id,
        vuln_type,
        severity,
        payload,
        f"Vulnerability found in parameter '{param}' at {url}",
        f"Payload '{payload}' triggered vulnerability detection",
        url,
        param,
        confidence
    ))
    conn.commit()

def get_vulnerabilities_for_scan(conn, scan_id, user_id, user_role):
    """Get all vulnerabilities for a specific scan."""
    # Check access
    scan = get_scan_by_id(conn, scan_id, user_id, user_role)
    
    c = conn.cursor()
    rows = c.execute("""
        SELECT * FROM Vulnerabilities 
        WHERE scan_id = ? 
        ORDER BY severity DESC, timestamp DESC
    """, (scan_id,)).fetchall()
    return rows

def save_graph_data(conn, scan_id: int, graph_data_json: str):
    """Save JSON-serialized graph analysis data for a scan."""
    c = conn.cursor()
    c.execute("UPDATE Scans SET graph_data = ? WHERE scan_id = ?", (graph_data_json, scan_id))
    conn.commit()

def get_graph_data(conn, scan_id: int) -> Optional[str]:
    """Get JSON-serialized graph analysis data for a scan."""
    c = conn.cursor()
    row = c.execute("SELECT graph_data FROM Scans WHERE scan_id = ?", (scan_id,)).fetchone()
    if row and row["graph_data"]:
        return row["graph_data"]
    return None

def create_report(conn, scan_id):
    """Create a report after scan completes."""
    # Get vulnerability count
    c = conn.cursor()
    count_row = c.execute(
        "SELECT COUNT(*) as count FROM Vulnerabilities WHERE scan_id = ?",
        (scan_id,)
    ).fetchone()
    total_vulns = count_row["count"] if count_row else 0
    
    # Create report
    summary = f"Scan completed with {total_vulns} vulnerabilities found"
    
    c.execute("""
        INSERT INTO Reports (user_id, scan_id, summary, total_vulns)
        SELECT user_id, ?, ?, ? FROM Scans WHERE scan_id = ?
    """, (scan_id, summary, total_vulns, scan_id))
    conn.commit()
    return c.lastrowid
# -------------------------------
if __name__ == "__main__":
    print("="*60)
    print("INITIALIZING DATABASE")
    print("="*60)
    print(f"Database file: {DB_NAME}")
    print(f"Current directory: {os.getcwd()}")
    print("Password hashing: bcrypt")
    print()
    
    try:
        init_database()
        ensure_admin_exists()
        print("\n" + "="*60)
        print("✓ DATABASE INITIALIZATION COMPLETE")
        print("="*60)
        
        # Show what was created
        conn = get_connection()
        c = conn.cursor()
        tables = c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        print(f"\nCreated {len(tables)} tables:")
        for table in tables:
            count = c.execute(f"SELECT COUNT(*) FROM {table[0]}").fetchone()[0]
            print(f"  - {table[0]}: {count} rows")
        conn.close()
        
        print("\n✓ Database is ready to use!")
        
    except Exception as e:
        print("\n" + "="*60)
        print("✗ DATABASE INITIALIZATION FAILED")
        print("="*60)
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()