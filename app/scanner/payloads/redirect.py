"""
scanner/payloads/redirect.py

Open Redirect payloads for vulnerability testing.
Tests for unvalidated redirects that could be used for phishing.
"""

from .base import Payload


def redirect_confirm(response_text: str) -> bool:
    """
    Check for open redirect indicators.
    This is mainly detected by checking response headers/redirects.
    """
    # Check if external domain appears in response
    indicators = [
        "evil.com",
        "attacker.com", 
        "example.com",
        "//evil",
        "http://evil",
        "https://evil",
    ]
    
    text_lower = response_text.lower()
    return any(ind.lower() in text_lower for ind in indicators)


REDIRECT_PAYLOADS = [
    # ============================================
    # BASIC OPEN REDIRECT
    # ============================================
    Payload(
        vuln_type="OpenRedirect",
        name="External URL",
        payload="https://evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Protocol-relative",
        payload="//evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Backslash bypass",
        payload="\\\\evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="At sign bypass",
        payload="https://legit.com@evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    
    # ============================================
    # ENCODED VARIANTS
    # ============================================
    Payload(
        vuln_type="OpenRedirect",
        name="URL encoded",
        payload="https%3A%2F%2Fevil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Double encoded",
        payload="https%253A%252F%252Fevil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    
    # ============================================
    # JAVASCRIPT REDIRECTS
    # ============================================
    Payload(
        vuln_type="OpenRedirect",
        name="JavaScript protocol",
        payload="javascript:location='https://evil.com'",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Data URL",
        payload="data:text/html,<script>location='https://evil.com'</script>",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),
]