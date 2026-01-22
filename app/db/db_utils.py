"""
db/db_utils.py

Database utility functions for better SQLite connection handling.
Provides connection with timeout and WAL mode for concurrent access.
"""

import sqlite3
import os
import logging

logger = logging.getLogger(__name__)

# Database file path
DB_NAME = os.environ.get("WEB_SCANNER_DB", "web_scanner.db")


def get_connection_with_timeout(timeout: int = 30):
    """
    Get a database connection with improved settings for concurrent access.
    
    Args:
        timeout: How long to wait for locks (seconds)
        
    Returns:
        sqlite3.Connection with optimized settings
    """
    conn = sqlite3.connect(
        DB_NAME, 
        check_same_thread=False,
        timeout=timeout  # Wait up to N seconds for locks
    )
    conn.row_factory = sqlite3.Row
    
    # Enable WAL mode for better concurrent read/write
    conn.execute("PRAGMA journal_mode=WAL;")
    
    # Set busy timeout (milliseconds)
    conn.execute(f"PRAGMA busy_timeout = {timeout * 1000};")
    
    # Enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON;")
    
    return conn


def execute_with_retry(conn, query: str, params: tuple = (), max_retries: int = 3):
    """
    Execute a query with retry logic for database locked errors.
    
    Args:
        conn: Database connection
        query: SQL query to execute
        params: Query parameters
        max_retries: Maximum number of retries
        
    Returns:
        Cursor after execution
    """
    import time
    
    last_error = None
    for attempt in range(max_retries):
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                last_error = e
                sleep_time = 0.1 * (2 ** attempt)  # Exponential backoff
                logger.warning(f"Database locked, retrying in {sleep_time}s (attempt {attempt + 1}/{max_retries})")
                time.sleep(sleep_time)
            else:
                raise
    
    # All retries failed
    raise last_error


def safe_commit(conn, max_retries: int = 3):
    """
    Commit with retry logic for database locked errors.
    """
    import time
    
    for attempt in range(max_retries):
        try:
            conn.commit()
            return
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                sleep_time = 0.1 * (2 ** attempt)
                logger.warning(f"Database locked on commit, retrying in {sleep_time}s")
                time.sleep(sleep_time)
            else:
                raise