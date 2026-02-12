"""
scanner/payloads/registry.py

Central registry for all vulnerability payloads.
Provides functions to retrieve payloads by type and context.
"""

from typing import List, Optional
from .base import Payload
from .xss import XSS_PAYLOADS
from .sqli import SQLI_PAYLOADS
from .traversal import TRAVERSAL_PAYLOADS
from .redirect import REDIRECT_PAYLOADS
from .header_injection import HEADER_INJECTION_PAYLOADS
from .nosql import NOSQL_PAYLOADS
from .ssti import SSTI_PAYLOADS
from .xxe import XXE_PAYLOADS
from .command_injection import COMMAND_INJECTION_PAYLOADS
from .ssrf import SSRF_PAYLOADS
from .idor import get_all_idor_payloads
from .auth_bypass import get_all_auth_bypass_payloads
from .security_headers import get_all_security_header_checks


# Master registry of all payload types
ALL_PAYLOADS = {
    "XSS": XSS_PAYLOADS,
    "SQLi": SQLI_PAYLOADS,
    "PathTraversal": TRAVERSAL_PAYLOADS,
    "OpenRedirect": REDIRECT_PAYLOADS,
    "HeaderInjection": HEADER_INJECTION_PAYLOADS,
    "NoSQL": NOSQL_PAYLOADS,
    "SSTI": SSTI_PAYLOADS,
    "XXE": XXE_PAYLOADS,
    "CommandInjection": COMMAND_INJECTION_PAYLOADS,
    "SSRF": SSRF_PAYLOADS,
}

# Extended payloads (dict-based)
EXTENDED_PAYLOADS = {
    "IDOR": get_all_idor_payloads(),
    "AuthBypass": get_all_auth_bypass_payloads(),
    "SecurityHeaders": get_all_security_header_checks(),
}

# Severity ordering for reporting
SEVERITY_ORDER = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0,
}


def get_payloads(
    vuln_type: str, 
    context: str = None, 
    safe_only: bool = True,
    severity_min: str = None
) -> List[Payload]:
    """
    Get payloads for a specific vulnerability type.
    
    Args:
        vuln_type: Type of vulnerability (XSS, SQLi, PathTraversal, etc.)
        context: Filter by context (url, form, header, json) - None for all
        safe_only: Only return safe payloads (default True)
        severity_min: Minimum severity level to include
        
    Returns:
        List of matching Payload objects
    """
    payloads = ALL_PAYLOADS.get(vuln_type, [])
    result = []
    
    min_severity_level = SEVERITY_ORDER.get(severity_min, 0) if severity_min else 0

    for p in payloads:
        # Filter by context
        if context and context not in p.contexts:
            continue
            
        # Filter by safe flag
        if safe_only and not p.safe:
            continue
            
        # Filter by minimum severity
        payload_severity = SEVERITY_ORDER.get(p.severity, 0)
        if payload_severity < min_severity_level:
            continue
            
        result.append(p)

    return result


def get_all_vuln_types() -> List[str]:
    """Get list of all supported vulnerability types."""
    return list(ALL_PAYLOADS.keys())


def get_payload_count(vuln_type: str = None) -> int:
    """
    Get count of payloads.
    
    Args:
        vuln_type: Specific type, or None for total count
        
    Returns:
        Number of payloads
    """
    if vuln_type:
        return len(ALL_PAYLOADS.get(vuln_type, []))
    else:
        return sum(len(p) for p in ALL_PAYLOADS.values())


def get_payloads_by_severity(severity: str) -> List[Payload]:
    """Get all payloads of a specific severity level."""
    result = []
    for payloads in ALL_PAYLOADS.values():
        for p in payloads:
            if p.severity == severity:
                result.append(p)
    return result


# Print summary when module loads (for debugging)
if __name__ == "__main__":
    print("Payload Registry Summary:")
    print("=" * 40)
    for vuln_type, payloads in ALL_PAYLOADS.items():
        print(f"{vuln_type}: {len(payloads)} payloads")
    print("=" * 40)
    print(f"Total: {get_payload_count()} payloads")