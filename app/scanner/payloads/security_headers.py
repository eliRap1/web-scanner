"""
Security Headers Analysis

Tests for missing or misconfigured security headers:
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Strict-Transport-Security (HSTS)
- Referrer-Policy
- Permissions-Policy
- Cache-Control
- And more...
"""

# Security headers to check
SECURITY_HEADERS = {
    # Critical headers
    'Content-Security-Policy': {
        'severity': 'high',
        'description': 'Prevents XSS, clickjacking, and other code injection attacks',
        'recommendation': "Add CSP header: Content-Security-Policy: default-src 'self'",
        'dangerous_values': [
            "unsafe-inline",
            "unsafe-eval",
            "data:",
            "*",
            "blob:",
        ],
    },
    'X-Frame-Options': {
        'severity': 'medium',
        'description': 'Prevents clickjacking attacks by controlling iframe embedding',
        'recommendation': 'Add header: X-Frame-Options: DENY or SAMEORIGIN',
        'valid_values': ['DENY', 'SAMEORIGIN'],
    },
    'X-Content-Type-Options': {
        'severity': 'medium',
        'description': 'Prevents MIME type sniffing attacks',
        'recommendation': 'Add header: X-Content-Type-Options: nosniff',
        'required_value': 'nosniff',
    },
    'Strict-Transport-Security': {
        'severity': 'high',
        'description': 'Enforces HTTPS connections (HSTS)',
        'recommendation': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
        'min_max_age': 31536000,  # 1 year
    },
    'Referrer-Policy': {
        'severity': 'low',
        'description': 'Controls how much referrer information is sent',
        'recommendation': 'Add header: Referrer-Policy: strict-origin-when-cross-origin',
        'secure_values': [
            'no-referrer',
            'no-referrer-when-downgrade',
            'strict-origin',
            'strict-origin-when-cross-origin',
            'same-origin',
        ],
    },
    'Permissions-Policy': {
        'severity': 'low',
        'description': 'Controls browser features and APIs',
        'recommendation': 'Add header: Permissions-Policy: geolocation=(), microphone=()',
        'check_for_dangerous': ['*'],
    },
    'X-XSS-Protection': {
        'severity': 'low',
        'description': 'Legacy XSS filter (deprecated but still useful for old browsers)',
        'recommendation': 'Add header: X-XSS-Protection: 1; mode=block',
        'note': 'Modern browsers use CSP instead',
    },

    # Information disclosure headers to check
    'Server': {
        'severity': 'info',
        'description': 'May expose server software version',
        'recommendation': 'Remove or genericize Server header',
        'type': 'info_disclosure',
    },
    'X-Powered-By': {
        'severity': 'info',
        'description': 'Exposes technology stack',
        'recommendation': 'Remove X-Powered-By header',
        'type': 'info_disclosure',
    },
    'X-AspNet-Version': {
        'severity': 'info',
        'description': 'Exposes ASP.NET version',
        'recommendation': 'Remove X-AspNet-Version header',
        'type': 'info_disclosure',
    },
    'X-AspNetMvc-Version': {
        'severity': 'info',
        'description': 'Exposes ASP.NET MVC version',
        'recommendation': 'Remove X-AspNetMvc-Version header',
        'type': 'info_disclosure',
    },

    # Cache headers
    'Cache-Control': {
        'severity': 'medium',
        'description': 'Controls caching of sensitive pages',
        'recommendation': 'For sensitive pages: Cache-Control: no-store, no-cache, must-revalidate, private',
        'check_for_auth_pages': True,
    },
    'Pragma': {
        'severity': 'low',
        'description': 'HTTP/1.0 cache control',
        'recommendation': 'For sensitive pages: Pragma: no-cache',
        'check_for_auth_pages': True,
    },
}

# Cookie security attributes to check
COOKIE_SECURITY_ATTRIBUTES = {
    'Secure': {
        'severity': 'high',
        'description': 'Cookie only sent over HTTPS',
        'recommendation': 'Add Secure flag to all authentication cookies',
    },
    'HttpOnly': {
        'severity': 'high',
        'description': 'Cookie not accessible via JavaScript',
        'recommendation': 'Add HttpOnly flag to prevent XSS cookie theft',
    },
    'SameSite': {
        'severity': 'medium',
        'description': 'CSRF protection via cookie scope',
        'recommendation': 'Add SameSite=Strict or SameSite=Lax',
        'secure_values': ['Strict', 'Lax'],
    },
    'Path': {
        'severity': 'low',
        'description': 'Restricts cookie to specific path',
        'recommendation': 'Set Path=/ or more restrictive',
    },
    'Domain': {
        'severity': 'low',
        'description': 'Restricts cookie to specific domain',
        'recommendation': 'Avoid setting Domain to allow subdomain access unless needed',
    },
    '__Secure-': {
        'severity': 'info',
        'description': 'Cookie prefix requiring Secure flag',
        'recommendation': 'Use __Secure- prefix for sensitive cookies',
        'type': 'prefix',
    },
    '__Host-': {
        'severity': 'info',
        'description': 'Strict cookie prefix (Secure, no Domain, Path=/)',
        'recommendation': 'Use __Host- prefix for session cookies',
        'type': 'prefix',
    },
}

# CSP directive analysis
CSP_DIRECTIVES = {
    'default-src': {'required': True, 'description': 'Fallback for other directives'},
    'script-src': {'critical': True, 'description': 'Controls script execution'},
    'style-src': {'critical': True, 'description': 'Controls style loading'},
    'img-src': {'description': 'Controls image loading'},
    'connect-src': {'description': 'Controls AJAX, WebSocket, fetch'},
    'font-src': {'description': 'Controls font loading'},
    'object-src': {'critical': True, 'description': 'Controls plugins (Flash, etc.)'},
    'media-src': {'description': 'Controls audio/video'},
    'frame-src': {'description': 'Controls iframe sources'},
    'frame-ancestors': {'critical': True, 'description': 'Controls who can embed this page'},
    'form-action': {'critical': True, 'description': 'Controls form submission targets'},
    'base-uri': {'critical': True, 'description': 'Controls base tag URL'},
    'upgrade-insecure-requests': {'description': 'Upgrades HTTP to HTTPS'},
    'block-all-mixed-content': {'description': 'Blocks HTTP resources on HTTPS pages'},
}

# Dangerous CSP values
CSP_DANGEROUS_VALUES = [
    {"value": "'unsafe-inline'", "severity": "high", "reason": "Allows inline scripts/styles, defeating XSS protection"},
    {"value": "'unsafe-eval'", "severity": "high", "reason": "Allows eval(), enabling XSS via code injection"},
    {"value": "data:", "severity": "medium", "reason": "Allows data: URIs which can contain scripts"},
    {"value": "blob:", "severity": "medium", "reason": "Allows blob: URIs which can execute code"},
    {"value": "*", "severity": "high", "reason": "Allows any source, providing no protection"},
    {"value": "http:", "severity": "medium", "reason": "Allows insecure HTTP resources"},
    {"value": "'unsafe-hashes'", "severity": "medium", "reason": "Allows specific inline handlers"},
]


def analyze_csp(csp_value: str) -> dict:
    """Analyze a Content-Security-Policy header value"""
    analysis = {
        'directives': {},
        'issues': [],
        'score': 100,
    }

    if not csp_value:
        return {'issues': ['No CSP header present'], 'score': 0}

    # Parse directives
    for directive in csp_value.split(';'):
        directive = directive.strip()
        if not directive:
            continue

        parts = directive.split()
        if len(parts) >= 1:
            name = parts[0].lower()
            values = parts[1:] if len(parts) > 1 else []
            analysis['directives'][name] = values

    # Check for dangerous values
    for directive, values in analysis['directives'].items():
        for value in values:
            for dangerous in CSP_DANGEROUS_VALUES:
                if dangerous['value'].lower() in value.lower():
                    analysis['issues'].append({
                        'directive': directive,
                        'value': value,
                        'severity': dangerous['severity'],
                        'reason': dangerous['reason'],
                    })
                    if dangerous['severity'] == 'high':
                        analysis['score'] -= 25
                    elif dangerous['severity'] == 'medium':
                        analysis['score'] -= 10

    # Check for missing critical directives
    for directive, info in CSP_DIRECTIVES.items():
        if info.get('critical') and directive not in analysis['directives']:
            if directive != 'default-src' or 'default-src' not in analysis['directives']:
                analysis['issues'].append({
                    'directive': directive,
                    'severity': 'medium',
                    'reason': f"Missing {directive} directive: {info['description']}",
                })
                analysis['score'] -= 5

    analysis['score'] = max(0, analysis['score'])
    return analysis


def get_all_security_header_checks():
    """Get all security header check configurations"""
    return {
        'headers': SECURITY_HEADERS,
        'cookie_attributes': COOKIE_SECURITY_ATTRIBUTES,
        'csp_directives': CSP_DIRECTIVES,
        'csp_dangerous_values': CSP_DANGEROUS_VALUES,
    }
