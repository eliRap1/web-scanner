"""
Remediation Guidance Module

This module provides detailed remediation guidance for each vulnerability type.
Each entry includes:
- Description of the vulnerability
- How it works (attack vector)
- Impact/risk assessment
- Step-by-step remediation instructions
- Code examples where applicable
- References to security standards (OWASP, CWE)
"""

REMEDIATION_GUIDE = {
    "XSS": {
        "name": "Cross-Site Scripting (XSS)",
        "severity_default": "high",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "description": """
            Cross-Site Scripting (XSS) occurs when an application includes untrusted data
            in a web page without proper validation or escaping. This allows attackers to
            execute malicious scripts in victims' browsers.
        """,
        "how_it_works": """
            1. Attacker identifies an input field that reflects user data in the page
            2. Attacker crafts a malicious payload containing JavaScript code
            3. When a victim views the page, the script executes in their browser
            4. The script can steal cookies, session tokens, or perform actions as the user
        """,
        "impact": [
            "Session hijacking and account takeover",
            "Theft of sensitive data (cookies, tokens)",
            "Defacement of web pages",
            "Phishing attacks using trusted domain",
            "Malware distribution"
        ],
        "remediation": [
            "Encode all user input before displaying in HTML (use HTML entity encoding)",
            "Use Content-Security-Policy (CSP) headers to restrict script sources",
            "Implement HttpOnly and Secure flags on session cookies",
            "Use modern frameworks that auto-escape output (React, Vue, Angular)",
            "Validate and sanitize all input on the server side",
            "Use textContent instead of innerHTML when setting element content"
        ],
        "code_example": {
            "vulnerable": """
<!-- VULNERABLE CODE -->
<div id="output"></div>
<script>
  document.getElementById('output').innerHTML = userInput;
</script>
            """,
            "secure": """
<!-- SECURE CODE -->
<div id="output"></div>
<script>
  // Use textContent instead of innerHTML
  document.getElementById('output').textContent = userInput;

  // Or use a library like DOMPurify
  document.getElementById('output').innerHTML = DOMPurify.sanitize(userInput);
</script>

// Server-side (Python/Flask example):
from markupsafe import escape
@app.route('/display')
def display():
    user_input = request.args.get('input', '')
    safe_input = escape(user_input)
    return render_template('page.html', content=safe_input)
            """
        },
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ]
    },

    "SQL Injection": {
        "name": "SQL Injection",
        "severity_default": "critical",
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "description": """
            SQL Injection occurs when untrusted data is sent to an interpreter as part of
            a command or query. The attacker's hostile data can trick the interpreter into
            executing unintended commands or accessing data without authorization.
        """,
        "how_it_works": """
            1. Application builds SQL queries using string concatenation with user input
            2. Attacker provides malicious input containing SQL syntax
            3. The database executes the modified query
            4. Attacker can read, modify, or delete data; bypass authentication
        """,
        "impact": [
            "Complete database compromise",
            "Data theft (credentials, personal info, financial data)",
            "Data modification or deletion",
            "Authentication bypass",
            "Remote code execution (in some cases)",
            "Full server compromise"
        ],
        "remediation": [
            "Use parameterized queries (prepared statements) for ALL database queries",
            "Use ORM frameworks that handle parameterization automatically",
            "Apply the principle of least privilege to database accounts",
            "Validate and sanitize all user input",
            "Use stored procedures with parameterized inputs",
            "Implement Web Application Firewall (WAF) as defense-in-depth"
        ],
        "code_example": {
            "vulnerable": """
# VULNERABLE CODE (Python)
query = "SELECT * FROM users WHERE username = '" + username + "'"
cursor.execute(query)

# VULNERABLE CODE (PHP)
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$result = mysqli_query($conn, $query);
            """,
            "secure": """
# SECURE CODE (Python with parameterized query)
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))

# SECURE CODE (Python with SQLAlchemy ORM)
user = session.query(User).filter(User.username == username).first()

# SECURE CODE (PHP with PDO)
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
            """
        },
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ]
    },

    "NoSQL Injection": {
        "name": "NoSQL Injection",
        "severity_default": "critical",
        "cwe": "CWE-943",
        "owasp": "A03:2021 - Injection",
        "description": """
            NoSQL Injection attacks target NoSQL databases (MongoDB, CouchDB, etc.) by
            injecting malicious operators or queries through user-controlled input.
        """,
        "how_it_works": """
            1. Application passes user input directly to NoSQL queries
            2. Attacker provides JSON operators like $gt, $ne, $where
            3. Database executes the modified query
            4. Attacker bypasses authentication or extracts data
        """,
        "impact": [
            "Authentication bypass",
            "Data extraction",
            "Data manipulation",
            "Denial of service"
        ],
        "remediation": [
            "Validate input types strictly (expect string, reject objects)",
            "Sanitize input by removing or escaping special characters",
            "Use query builders instead of raw query construction",
            "Implement strict schema validation",
            "Disable JavaScript execution in MongoDB if not needed"
        ],
        "code_example": {
            "vulnerable": """
# VULNERABLE CODE (Node.js/MongoDB)
db.users.find({ username: req.body.username, password: req.body.password })
# Attacker sends: { "username": "admin", "password": { "$ne": "" } }
            """,
            "secure": """
# SECURE CODE (Node.js/MongoDB)
// Validate that inputs are strings
if (typeof username !== 'string' || typeof password !== 'string') {
    throw new Error('Invalid input type');
}
db.users.find({ username: username, password: password })

// Or use mongoose with strict schema
const userSchema = new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
}, { strict: true });
            """
        },
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"
        ]
    },

    "Path Traversal": {
        "name": "Path Traversal / Directory Traversal",
        "severity_default": "high",
        "cwe": "CWE-22",
        "owasp": "A01:2021 - Broken Access Control",
        "description": """
            Path Traversal attacks exploit insufficient input validation to access files
            and directories stored outside the intended folder. Using sequences like
            '../', attackers can navigate the file system.
        """,
        "how_it_works": """
            1. Application uses user input to construct file paths
            2. Attacker provides path traversal sequences (../, ..\\)
            3. Application accesses files outside the intended directory
            4. Attacker reads sensitive files (/etc/passwd, config files, source code)
        """,
        "impact": [
            "Access to sensitive system files",
            "Source code disclosure",
            "Configuration file exposure",
            "Credential theft",
            "Potential remote code execution"
        ],
        "remediation": [
            "Use a whitelist of allowed files/directories",
            "Canonicalize paths and validate they're within allowed directory",
            "Use built-in path joining functions that prevent traversal",
            "Implement chroot jails or sandboxing",
            "Avoid passing user input directly to file system functions"
        ],
        "code_example": {
            "vulnerable": """
# VULNERABLE CODE (Python)
filename = request.args.get('file')
with open('/var/www/files/' + filename, 'r') as f:
    return f.read()
# Attacker sends: ?file=../../../etc/passwd
            """,
            "secure": """
# SECURE CODE (Python)
import os
from pathlib import Path

ALLOWED_DIR = Path('/var/www/files').resolve()

filename = request.args.get('file')
# Construct full path and resolve to absolute
requested_path = (ALLOWED_DIR / filename).resolve()

# Verify the path is within allowed directory
if not str(requested_path).startswith(str(ALLOWED_DIR)):
    abort(403)  # Forbidden

with open(requested_path, 'r') as f:
    return f.read()
            """
        },
        "references": [
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://cwe.mitre.org/data/definitions/22.html"
        ]
    },

    "Open Redirect": {
        "name": "Open Redirect",
        "severity_default": "medium",
        "cwe": "CWE-601",
        "owasp": "A01:2021 - Broken Access Control",
        "description": """
            Open Redirect occurs when an application redirects users to a URL specified
            in user-controlled input without proper validation, allowing attackers to
            redirect victims to malicious sites.
        """,
        "how_it_works": """
            1. Application has a redirect parameter (e.g., ?redirect=, ?next=, ?url=)
            2. Attacker crafts a link with a malicious redirect URL
            3. Victim clicks link thinking it's legitimate (shows trusted domain)
            4. Application redirects victim to attacker's malicious site
        """,
        "impact": [
            "Phishing attacks leveraging trusted domain",
            "Credential theft via fake login pages",
            "Malware distribution",
            "OAuth token theft"
        ],
        "remediation": [
            "Avoid using user-controlled data for redirects",
            "Use a whitelist of allowed redirect destinations",
            "Validate that redirect URLs are relative (start with /)",
            "Validate the host portion matches your domain",
            "Use indirect references (map IDs to URLs server-side)"
        ],
        "code_example": {
            "vulnerable": """
# VULNERABLE CODE (Python/Flask)
@app.route('/redirect')
def do_redirect():
    url = request.args.get('url')
    return redirect(url)
# Attacker: /redirect?url=https://evil.com
            """,
            "secure": """
# SECURE CODE (Python/Flask)
from urllib.parse import urlparse

ALLOWED_HOSTS = ['example.com', 'www.example.com']

@app.route('/redirect')
def do_redirect():
    url = request.args.get('url', '/')

    # Only allow relative URLs
    if url.startswith('/') and not url.startswith('//'):
        return redirect(url)

    # Or validate against whitelist
    parsed = urlparse(url)
    if parsed.netloc in ALLOWED_HOSTS:
        return redirect(url)

    return redirect('/')  # Default to home
            """
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
        ]
    },

    "SSTI": {
        "name": "Server-Side Template Injection (SSTI)",
        "severity_default": "critical",
        "cwe": "CWE-1336",
        "owasp": "A03:2021 - Injection",
        "description": """
            SSTI occurs when user input is embedded directly into a template engine's
            template, allowing attackers to inject template directives and execute
            arbitrary code on the server.
        """,
        "how_it_works": """
            1. Application uses template engine (Jinja2, Twig, FreeMarker, etc.)
            2. User input is directly embedded in template string
            3. Attacker injects template syntax (e.g., {{7*7}})
            4. Template engine evaluates the expression, potentially executing code
        """,
        "impact": [
            "Remote code execution on server",
            "Complete server compromise",
            "Data theft",
            "Lateral movement in network"
        ],
        "remediation": [
            "Never pass user input directly to template.render()",
            "Pass user data as context variables, not template content",
            "Use sandboxed template environments",
            "Implement strict input validation",
            "Use logic-less template engines when possible"
        ],
        "code_example": {
            "vulnerable": """
# VULNERABLE CODE (Python/Jinja2)
from jinja2 import Template
template_string = request.args.get('template')
Template(template_string).render()
# Attacker: ?template={{config.items()}}
            """,
            "secure": """
# SECURE CODE (Python/Jinja2)
from jinja2 import Environment, FileSystemLoader, select_autoescape

# Use file-based templates, not string templates
env = Environment(
    loader=FileSystemLoader('templates'),
    autoescape=select_autoescape(['html', 'xml'])
)

# Pass user input as context, not as template
template = env.get_template('page.html')
return template.render(user_input=request.args.get('name'))
            """
        },
        "references": [
            "https://portswigger.net/research/server-side-template-injection"
        ]
    },

    "Command Injection": {
        "name": "OS Command Injection",
        "severity_default": "critical",
        "cwe": "CWE-78",
        "owasp": "A03:2021 - Injection",
        "description": """
            Command Injection occurs when an application passes unsafe user-supplied data
            to a system shell. Attackers can execute arbitrary operating system commands
            with the privileges of the vulnerable application.
        """,
        "how_it_works": """
            1. Application builds shell commands using user input
            2. Attacker provides input with command separators (;, |, &&)
            3. Shell executes the injected command
            4. Attacker gains shell access to the server
        """,
        "impact": [
            "Full server compromise",
            "Data theft or destruction",
            "Malware installation",
            "Pivot point for further attacks",
            "Ransomware deployment"
        ],
        "remediation": [
            "Avoid calling OS commands from application code",
            "Use language-native libraries instead of shell commands",
            "If shell is necessary, use parameterized commands (subprocess with list)",
            "Implement strict input validation with whitelist",
            "Run with minimal privileges"
        ],
        "code_example": {
            "vulnerable": """
# VULNERABLE CODE (Python)
import os
filename = request.args.get('filename')
os.system('cat ' + filename)
# Attacker: ?filename=file.txt; rm -rf /
            """,
            "secure": """
# SECURE CODE (Python)
import subprocess

filename = request.args.get('filename')

# Validate input against whitelist
if not filename.isalnum():
    abort(400)

# Use subprocess with list (no shell)
result = subprocess.run(
    ['cat', filename],
    capture_output=True,
    text=True,
    shell=False  # Important: never use shell=True with user input
)
return result.stdout
            """
        },
        "references": [
            "https://owasp.org/www-community/attacks/Command_Injection"
        ]
    },

    "SSRF": {
        "name": "Server-Side Request Forgery (SSRF)",
        "severity_default": "high",
        "cwe": "CWE-918",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "description": """
            SSRF occurs when an application fetches a remote resource using a user-supplied
            URL without proper validation. Attackers can make requests to internal services,
            cloud metadata endpoints, or other protected resources.
        """,
        "how_it_works": """
            1. Application accepts URL from user and fetches it server-side
            2. Attacker provides URL to internal service (localhost, 169.254.169.254)
            3. Server fetches the internal resource
            4. Attacker receives sensitive internal data or performs actions
        """,
        "impact": [
            "Access to internal services",
            "Cloud metadata credential theft (AWS keys, etc.)",
            "Internal network scanning",
            "Bypass of firewalls and access controls",
            "Remote code execution via internal services"
        ],
        "remediation": [
            "Validate and sanitize all user-supplied URLs",
            "Use allowlist of permitted domains/IPs",
            "Block requests to private IP ranges and localhost",
            "Disable unnecessary URL schemes (file://, gopher://)",
            "Use network segmentation",
            "Block access to cloud metadata endpoints"
        ],
        "code_example": {
            "vulnerable": """
# VULNERABLE CODE (Python)
import requests
url = request.args.get('url')
response = requests.get(url)
return response.text
# Attacker: ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
            """,
            "secure": """
# SECURE CODE (Python)
import requests
import ipaddress
from urllib.parse import urlparse

BLOCKED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0']
ALLOWED_SCHEMES = ['http', 'https']

def is_safe_url(url):
    parsed = urlparse(url)

    # Check scheme
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False

    # Check for blocked hosts
    if parsed.hostname in BLOCKED_HOSTS:
        return False

    # Check for private IP ranges
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
    except ValueError:
        pass  # Not an IP address

    return True

url = request.args.get('url')
if not is_safe_url(url):
    abort(400, 'Invalid URL')
response = requests.get(url, timeout=5)
            """
        },
        "references": [
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"
        ]
    },

    "XXE": {
        "name": "XML External Entity (XXE) Injection",
        "severity_default": "high",
        "cwe": "CWE-611",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": """
            XXE occurs when XML input containing a reference to an external entity is
            processed by a weakly configured XML parser. Attackers can use external
            entities to access files, perform SSRF, or cause denial of service.
        """,
        "how_it_works": """
            1. Application parses XML from user input
            2. Attacker includes DOCTYPE with external entity definition
            3. Parser resolves the external entity (file, URL)
            4. Content of file/URL is included in response or error
        """,
        "impact": [
            "Local file disclosure",
            "Server-side request forgery",
            "Denial of service (billion laughs attack)",
            "Port scanning",
            "Remote code execution (rare)"
        ],
        "remediation": [
            "Disable DTDs (Document Type Definitions) completely",
            "Disable external entity processing",
            "Use less complex data formats (JSON) when possible",
            "Validate and sanitize XML input",
            "Keep XML processors updated"
        ],
        "code_example": {
            "vulnerable": """
# VULNERABLE CODE (Python)
from lxml import etree
xml_data = request.data
doc = etree.fromstring(xml_data)  # Vulnerable to XXE
            """,
            "secure": """
# SECURE CODE (Python with lxml)
from lxml import etree

xml_data = request.data
parser = etree.XMLParser(
    resolve_entities=False,  # Disable entity resolution
    no_network=True,         # Disable network access
    dtd_validation=False,    # Disable DTD validation
    load_dtd=False           # Don't load DTD
)
doc = etree.fromstring(xml_data, parser=parser)

# SECURE CODE (Python with defusedxml - recommended)
import defusedxml.ElementTree as ET
doc = ET.fromstring(xml_data)  # Safe by default
            """
        },
        "references": [
            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"
        ]
    },

    "Header Injection": {
        "name": "HTTP Header Injection / CRLF Injection",
        "severity_default": "medium",
        "cwe": "CWE-113",
        "owasp": "A03:2021 - Injection",
        "description": """
            Header Injection occurs when user input is included in HTTP response headers
            without proper sanitization. By injecting CRLF (\\r\\n) sequences, attackers
            can add arbitrary headers or split the response.
        """,
        "how_it_works": """
            1. Application includes user input in response headers
            2. Attacker provides input with CRLF characters
            3. New headers are injected into the response
            4. Can lead to XSS, cache poisoning, or session fixation
        """,
        "impact": [
            "Cross-site scripting via injected content",
            "Cache poisoning",
            "Session fixation attacks",
            "HTTP response splitting"
        ],
        "remediation": [
            "Never include raw user input in HTTP headers",
            "Strip or encode CR (\\r) and LF (\\n) characters",
            "Use framework functions that sanitize header values",
            "Validate input against strict patterns"
        ],
        "code_example": {
            "vulnerable": """
# VULNERABLE CODE (Python/Flask)
@app.route('/redirect')
def redirect_user():
    location = request.args.get('url')
    response = make_response()
    response.headers['Location'] = location
    return response
# Attacker: ?url=http://example.com%0d%0aSet-Cookie:%20session=evil
            """,
            "secure": """
# SECURE CODE (Python/Flask)
import re

@app.route('/redirect')
def redirect_user():
    location = request.args.get('url', '/')

    # Remove any CRLF characters
    safe_location = re.sub(r'[\\r\\n]', '', location)

    # Or validate URL format strictly
    if not re.match(r'^https?://[a-zA-Z0-9.-]+/', safe_location):
        safe_location = '/'

    return redirect(safe_location)
            """
        },
        "references": [
            "https://owasp.org/www-community/attacks/HTTP_Response_Splitting"
        ]
    },

    "IDOR": {
        "name": "Insecure Direct Object Reference (IDOR)",
        "severity_default": "high",
        "cwe": "CWE-639",
        "owasp": "A01:2021 - Broken Access Control",
        "description": """
            IDOR occurs when an application exposes internal implementation objects
            (like database IDs) directly in URLs or parameters without proper
            authorization checks, allowing users to access other users' data.
        """,
        "how_it_works": """
            1. Application uses predictable identifiers (IDs) in URLs
            2. User modifies the ID to another value (e.g., user_id=2 instead of 1)
            3. Application returns data without verifying ownership
            4. Attacker accesses other users' data or performs unauthorized actions
        """,
        "impact": [
            "Unauthorized access to other users' data",
            "Privacy violations",
            "Data theft",
            "Account takeover",
            "Regulatory compliance violations (GDPR, etc.)"
        ],
        "remediation": [
            "Implement proper access control checks on every request",
            "Verify user owns the requested resource before returning it",
            "Use indirect references (map user's resources to random tokens)",
            "Use UUIDs instead of sequential IDs (defense in depth)",
            "Log and monitor access patterns for anomalies"
        ],
        "code_example": {
            "vulnerable": """
# VULNERABLE CODE (Python/Flask)
@app.route('/api/user/<user_id>')
def get_user(user_id):
    user = db.query(User).get(user_id)
    return jsonify(user.to_dict())  # No authorization check!
# Attacker changes user_id to access any user's data
            """,
            "secure": """
# SECURE CODE (Python/Flask)
@app.route('/api/user/<user_id>')
@login_required
def get_user(user_id):
    # Verify the requesting user owns this resource
    if current_user.id != int(user_id) and not current_user.is_admin:
        abort(403, 'Access denied')

    user = db.query(User).get(user_id)
    if not user:
        abort(404)
    return jsonify(user.to_dict())
            """
        },
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"
        ]
    },

    "CORS Misconfiguration": {
        "name": "CORS Misconfiguration",
        "severity_default": "high",
        "cwe": "CWE-346",
        "owasp": "A01:2021 - Broken Access Control",
        "description": """
            CORS (Cross-Origin Resource Sharing) misconfiguration occurs when a web
            application allows requests from untrusted origins, potentially allowing
            attackers to make authenticated requests and steal sensitive data.
        """,
        "how_it_works": """
            1. Server allows arbitrary origins via Access-Control-Allow-Origin
            2. Attacker hosts malicious page on their domain
            3. Victim visits attacker's page while logged into target site
            4. Attacker's JavaScript makes cross-origin requests with victim's cookies
            5. Sensitive data is returned and stolen by attacker
        """,
        "impact": [
            "Cross-origin data theft",
            "Credential theft",
            "Session hijacking",
            "Unauthorized actions on behalf of users"
        ],
        "remediation": [
            "Only allow specific, trusted origins",
            "Never use wildcard (*) with credentials",
            "Validate Origin header against whitelist",
            "Don't reflect arbitrary Origin headers",
            "Use null origin only when necessary"
        ],
        "code_example": {
            "vulnerable": """
# VULNERABLE CODE (Python/Flask)
@app.after_request
def add_cors(response):
    origin = request.headers.get('Origin')
    response.headers['Access-Control-Allow-Origin'] = origin  # Reflects any origin!
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response
            """,
            "secure": """
# SECURE CODE (Python/Flask)
ALLOWED_ORIGINS = ['https://trusted-site.com', 'https://app.example.com']

@app.after_request
def add_cors(response):
    origin = request.headers.get('Origin')

    # Only allow whitelisted origins
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'

    return response
            """
        },
        "references": [
            "https://portswigger.net/web-security/cors"
        ]
    },

    "Missing Security Header": {
        "name": "Missing Security Headers",
        "severity_default": "medium",
        "cwe": "CWE-693",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": """
            Security headers provide an additional layer of protection against various
            attacks. Missing headers leave the application vulnerable to XSS, clickjacking,
            MIME sniffing, and other client-side attacks.
        """,
        "how_it_works": """
            1. Application doesn't set security headers in responses
            2. Browser doesn't apply protective measures
            3. Attackers can exploit the lack of protection
            4. XSS, clickjacking, and other attacks become easier
        """,
        "impact": [
            "Increased XSS attack surface",
            "Clickjacking attacks",
            "MIME type sniffing vulnerabilities",
            "Insecure connections"
        ],
        "remediation": [
            "Add Content-Security-Policy header",
            "Add X-Frame-Options: DENY or SAMEORIGIN",
            "Add X-Content-Type-Options: nosniff",
            "Add Strict-Transport-Security for HTTPS",
            "Add Referrer-Policy header",
            "Set Secure, HttpOnly, and SameSite on cookies"
        ],
        "code_example": {
            "vulnerable": """
# No security headers configured
            """,
            "secure": """
# SECURE CODE (Python/Flask)
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# For cookies
response.set_cookie('session', value, secure=True, httponly=True, samesite='Strict')
            """
        },
        "references": [
            "https://owasp.org/www-project-secure-headers/"
        ]
    },

    "Auth Bypass": {
        "name": "Authentication Bypass",
        "severity_default": "critical",
        "cwe": "CWE-287",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "description": """
            Authentication bypass vulnerabilities allow attackers to access protected
            resources without proper authentication, often through parameter tampering,
            header injection, or exploiting logic flaws.
        """,
        "how_it_works": """
            1. Attacker identifies authentication mechanism
            2. Manipulates parameters, headers, or requests
            3. Application fails to properly validate authentication
            4. Attacker gains unauthorized access
        """,
        "impact": [
            "Complete authentication bypass",
            "Unauthorized access to sensitive data",
            "Account takeover",
            "Privilege escalation"
        ],
        "remediation": [
            "Implement proper server-side authentication",
            "Never trust client-side authentication checks",
            "Use secure session management",
            "Implement multi-factor authentication",
            "Log and monitor authentication attempts"
        ],
        "code_example": {
            "vulnerable": """
# VULNERABLE CODE - trusts client-side check
@app.route('/admin')
def admin_panel():
    is_admin = request.args.get('admin', 'false')
    if is_admin == 'true':
        return render_template('admin.html')
    return redirect('/login')
            """,
            "secure": """
# SECURE CODE - server-side verification
@app.route('/admin')
@login_required
def admin_panel():
    # Check admin status from server-side session
    if not current_user.is_admin:
        abort(403)
    return render_template('admin.html')
            """
        },
        "references": [
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
        ]
    }
}


def get_remediation(vuln_type: str) -> dict:
    """
    Get remediation guidance for a vulnerability type.

    Args:
        vuln_type: The type of vulnerability (e.g., 'XSS', 'SQL Injection')

    Returns:
        dict: Remediation guidance or default guidance if type not found
    """
    # Try exact match first
    if vuln_type in REMEDIATION_GUIDE:
        return REMEDIATION_GUIDE[vuln_type]

    # Try case-insensitive match
    vuln_lower = vuln_type.lower()
    for key, value in REMEDIATION_GUIDE.items():
        if key.lower() == vuln_lower:
            return value

    # Try partial match
    for key, value in REMEDIATION_GUIDE.items():
        if key.lower() in vuln_lower or vuln_lower in key.lower():
            return value

    # Return default guidance
    return {
        "name": vuln_type,
        "severity_default": "medium",
        "cwe": "N/A",
        "owasp": "See OWASP Top 10",
        "description": f"A {vuln_type} vulnerability was detected.",
        "how_it_works": "This vulnerability may allow attackers to compromise the application.",
        "impact": ["Potential security breach", "Data exposure", "System compromise"],
        "remediation": [
            "Review the affected code for security issues",
            "Implement input validation",
            "Follow secure coding practices",
            "Consult OWASP guidelines for this vulnerability type"
        ],
        "code_example": None,
        "references": ["https://owasp.org/www-project-top-ten/"]
    }


def get_all_vulnerability_types() -> list:
    """
    Get a list of all documented vulnerability types.

    Returns:
        list: List of vulnerability type names
    """
    return list(REMEDIATION_GUIDE.keys())
