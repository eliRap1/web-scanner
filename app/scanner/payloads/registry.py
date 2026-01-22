from .xss import XSS_PAYLOADS
from .sqli import SQLI_PAYLOADS
from .traversal import TRAVERSAL_PAYLOADS

ALL_PAYLOADS = {
    "XSS": XSS_PAYLOADS,
    "SQLi": SQLI_PAYLOADS,
    "PathTraversal": TRAVERSAL_PAYLOADS
}

def get_payloads(vuln_type: str, context: str, safe_only: bool = True):
    payloads = ALL_PAYLOADS.get(vuln_type, [])
    result = []

    for p in payloads:
        if context in p.contexts:
            if safe_only and not p.safe:
                continue
            result.append(p)

    return result
