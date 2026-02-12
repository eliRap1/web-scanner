# Web Vulnerability Scanner - Complete Project Documentation

A full-stack web application security scanner that automatically discovers and tests web applications for security vulnerabilities.

---

## Table of Contents

1. [Overview](#overview)
2. [Technology Stack](#technology-stack)
3. [Project Structure](#project-structure)
4. [Installation & Setup](#installation--setup)
5. [Architecture](#architecture)
6. [Backend Components](#backend-components)
7. [Scanner Engine](#scanner-engine)
8. [Vulnerability Testing](#vulnerability-testing)
9. [Payload System](#payload-system)
10. [Database Schema](#database-schema)
11. [API Reference](#api-reference)
12. [Frontend UI](#frontend-ui)
13. [Authentication System](#authentication-system)
14. [Report Generation](#report-generation)
15. [Task Queue & Workers](#task-queue--workers)
16. [Configuration](#configuration)
17. [Scanning Flow](#scanning-flow)

---

## Overview

This web vulnerability scanner is a comprehensive security testing tool that combines:

- **Automated Crawling**: Playwright-based browser automation that discovers pages, forms, and API endpoints
- **Vulnerability Detection**: Tests for 10+ vulnerability types using 67+ payloads
- **False Positive Reduction**: Multi-stage confirmation and confidence scoring
- **Multi-User Support**: Role-based access control with authentication
- **Real-Time Monitoring**: Live progress updates during scans
- **Professional Reporting**: HTML/PDF reports with detailed findings

### Key Capabilities

| Feature | Description |
|---------|-------------|
| JavaScript Rendering | Full browser execution via Playwright |
| SPA Support | Detects React/Vue/Angular routing |
| Form Discovery | Automatic form detection with CSRF handling |
| 10+ Vuln Types | XSS, SQLi, NoSQLi, SSTI, XXE, Command Injection, SSRF, Path Traversal, Open Redirect, Header Injection |
| Confidence Scoring | 0-100% confidence ratings on findings |
| Concurrent Scanning | Multiple simultaneous scans with queue management |
| Report Generation | HTML and PDF export with risk scoring |

---

## Technology Stack

### Backend
- **Python 3.10+** - Core language
- **FastAPI** - Web framework with async support
- **Uvicorn** - ASGI server
- **Playwright** - Browser automation for crawling
- **SQLite** - Database storage
- **bcrypt** - Password hashing
- **Jinja2** - Template rendering
- **WeasyPrint** - PDF generation (optional)

### Frontend
- **React 18** - UI framework
- **TypeScript** - Type-safe JavaScript
- **Vite** - Build tool and dev server
- **React Router** - Client-side routing
- **CSS3** - Dark theme styling

---

## Project Structure

```
web-scanner/
├── app/                              # Backend Application
│   ├── main.py                       # FastAPI entry point
│   ├── api/
│   │   └── auth/
│   │       ├── login.py              # Login, token, logout endpoints
│   │       └── register.py           # User registration
│   ├── db/
│   │   ├── database.py               # Database models & migrations
│   │   ├── db_utils.py               # Database utilities
│   │   └── backup.py                 # Backup functionality
│   ├── scanner/
│   │   ├── engine.py                 # ProductionCrawler class
│   │   ├── vulnerability_tester.py   # VulnerabilityTester class
│   │   ├── task_queue.py             # Job queue management
│   │   ├── worker.py                 # Background worker thread
│   │   ├── models.py                 # Data classes (Form, ScanTarget)
│   │   ├── extractor.py              # HTML form/link extraction
│   │   ├── scope.py                  # URL scope validation
│   │   ├── http_client.py            # HTTP request utilities
│   │   ├── auth_manager.py           # Target authentication
│   │   └── payloads/                 # Vulnerability payloads
│   │       ├── base.py               # Payload dataclass
│   │       ├── registry.py           # Central payload registry
│   │       ├── xss.py                # XSS payloads (16)
│   │       ├── sqli.py               # SQL injection payloads (18)
│   │       ├── nosql.py              # NoSQL injection payloads
│   │       ├── ssti.py               # Template injection payloads
│   │       ├── xxe.py                # XML External Entity payloads
│   │       ├── command_injection.py  # OS command injection
│   │       ├── ssrf.py               # Server-side request forgery
│   │       ├── traversal.py          # Path traversal payloads (20)
│   │       ├── redirect.py           # Open redirect payloads (8)
│   │       └── header_injection.py   # CRLF injection payloads (5)
│   ├── reports/
│   │   ├── generator.py              # ReportGenerator class
│   │   ├── reports_router.py         # Report API endpoints
│   │   └── templates/                # HTML/PDF templates
│   ├── scans/
│   │   └── scans_router.py           # Scan API endpoints
│   └── security/
│       └── middleware.py             # Authentication middleware
│
├── web-scanner-ui/                   # Frontend Application
│   ├── src/
│   │   ├── App.tsx                   # Main app with routing
│   │   ├── main.tsx                  # React entry point
│   │   ├── index.css                 # Global styles (dark theme)
│   │   ├── pages/
│   │   │   ├── Login.tsx             # Login page
│   │   │   ├── Register.tsx          # Registration page
│   │   │   ├── Dashboard.tsx         # Main dashboard
│   │   │   ├── NewScan.tsx           # Scan creation & monitoring
│   │   │   └── Reports.tsx           # Report viewing
│   │   ├── components/
│   │   │   └── Sidebar.tsx           # Navigation sidebar
│   │   └── api/
│   │       └── client.ts             # API client configuration
│   ├── package.json                  # Dependencies
│   └── vite.config.ts                # Vite configuration
│
├── reports/                          # Generated reports directory
├── web_scanner.db                    # SQLite database
└── README.md                         # Basic readme
```

---

## Installation & Setup

### Prerequisites
- Python 3.10 or higher
- Node.js 18 or higher
- npm or yarn

### Backend Setup

```bash
# Clone repository
cd web-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install fastapi uvicorn playwright requests bcrypt jinja2

# Install Playwright browsers
playwright install chromium

# Start backend server
uvicorn app.main:app --reload --port 8000
```

### Frontend Setup

```bash
# Navigate to frontend directory
cd web-scanner-ui

# Install dependencies
npm install

# Start development server
npm run dev
```

### Default Access
- **Backend API**: http://localhost:8000
- **Frontend UI**: http://localhost:5173
- **API Documentation**: http://localhost:8000/docs

### Default Admin Credentials
- **Username**: admin
- **Password**: Admin@123

---

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        FRONTEND (React)                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │  Login   │  │Dashboard │  │ NewScan  │  │ Reports  │        │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
└───────┼─────────────┼─────────────┼─────────────┼───────────────┘
        │             │             │             │
        └─────────────┴──────┬──────┴─────────────┘
                             │ HTTP/REST
┌────────────────────────────┼────────────────────────────────────┐
│                      BACKEND (FastAPI)                          │
│  ┌─────────────────────────┼─────────────────────────────────┐  │
│  │              Authentication Middleware                     │  │
│  └─────────────────────────┼─────────────────────────────────┘  │
│                            │                                    │
│  ┌──────────┐  ┌──────────┴───────────┐  ┌──────────────────┐  │
│  │   Auth   │  │    Scans Router      │  │  Reports Router  │  │
│  │  Router  │  │  (Start/Status/Logs) │  │  (Generate/View) │  │
│  └────┬─────┘  └──────────┬───────────┘  └────────┬─────────┘  │
│       │                   │                       │             │
│  ┌────┴───────────────────┴───────────────────────┴──────────┐  │
│  │                    Database Layer (SQLite)                 │  │
│  │  Users │ Sessions │ Scans │ Forms │ Vulnerabilities │ Logs │  │
│  └───────────────────────────────────────────────────────────┘  │
│                            │                                    │
│  ┌─────────────────────────┼─────────────────────────────────┐  │
│  │                   Scanner Engine                           │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐  │  │
│  │  │  Task Queue  │  │   Crawler    │  │  Vuln Tester    │  │  │
│  │  │  & Workers   │  │ (Playwright) │  │  (67+ Payloads) │  │  │
│  │  └──────────────┘  └──────────────┘  └─────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Request Flow

1. User authenticates via `/login` endpoint
2. Token stored in localStorage, sent with each request
3. Middleware validates token and attaches user to request
4. Router handles request and interacts with database/scanner
5. Scanner runs in background thread with job queue
6. Progress updates available via polling endpoints

---

## Backend Components

### Main Application (`app/main.py`)

The FastAPI application entry point handles:

- **Lifespan Management**: Database initialization on startup
- **Middleware Registration**: CORS and authentication
- **Router Registration**: Auth, scans, and reports endpoints
- **Startup Recovery**: Marks stuck scans as failed on restart
- **Admin Creation**: Creates default admin user if none exists

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database
    init_db()
    # Create admin user
    create_admin_user()
    # Recover stuck scans
    recover_stuck_scans()
    yield
```

### Authentication Middleware (`security/middleware.py`)

Validates requests by:
1. Checking for `Authorization: Bearer <token>` header
2. Looking up token in Sessions table
3. Verifying token hasn't expired
4. Attaching user info to `request.state.user`

**Public Endpoints** (no auth required):
- `/login`, `/register`, `/verify`
- `/health`, `/docs`, `/openapi.json`

---

## Scanner Engine

### ProductionCrawler (`scanner/engine.py`)

The crawler uses Playwright to render JavaScript and discover content using 10+ techniques:

#### Discovery Methods

| Method | Description |
|--------|-------------|
| **Network Interception** | Captures all HTTP requests made by JavaScript |
| **Link Extraction** | Parses all `<a href="">` tags |
| **Form Discovery** | Finds forms with method, action, and field details |
| **JavaScript URL Extraction** | Regex patterns to find URLs in JS code |
| **Click Discovery** | Clicks buttons, tabs, accordions to reveal hidden content |
| **Scroll Discovery** | Scrolls to trigger lazy-loading |
| **SPA Route Discovery** | Detects React/Vue/Angular routing patterns |
| **Sitemap/Robots.txt** | Extracts URLs from sitemap.xml and robots.txt |
| **Data Attribute Extraction** | Finds data-url, data-href, data-action attributes |
| **HTML Comment Parsing** | Searches comments for hidden URLs |

#### Crawler Configuration

```python
crawler = ProductionCrawler(
    max_pages=30,           # Maximum pages to visit
    max_depth=5,            # Maximum link depth
    timeout=30000,          # Page load timeout (ms)
    wait_for_idle=True,     # Wait for network idle
    click_discovery=True,   # Click elements for discovery
    scroll_discovery=True,  # Scroll for lazy loading
    js_extraction=True      # Extract URLs from JavaScript
)
```

#### Output

```python
@dataclass
class CrawlResult:
    pages_visited: List[str]
    forms_found: List[Form]
    urls_discovered: List[str]
    api_endpoints: List[str]
    parameters: Dict[str, List[str]]
```

---

## Vulnerability Testing

### VulnerabilityTester (`scanner/vulnerability_tester.py`)

The tester uses multiple detection strategies to find vulnerabilities with high accuracy.

#### Detection Methods

| Method | Description | Example |
|--------|-------------|---------|
| **Error-Based** | Looks for database error patterns | "You have an error in your SQL syntax" |
| **Boolean-Based** | Compares true/false condition responses | `1=1` vs `1=2` response differences |
| **Time-Based** | Measures response delays | `SLEEP(5)` causing 5+ second delay |
| **Confirmation Tests** | Multi-stage validation | Re-tests with variations to confirm |
| **Context Analysis** | Understands where payloads land | Reflected vs stored vs DOM-based |
| **Baseline Comparison** | Compares against normal behavior | Response size/content differences |

#### Confidence Scoring

The tester assigns confidence scores from 0.0 to 1.0:

| Score Range | Confidence Level | Interpretation |
|-------------|------------------|----------------|
| 0.90 - 1.00 | Very High | Almost certainly vulnerable |
| 0.80 - 0.89 | High | Likely vulnerable |
| 0.70 - 0.79 | Medium | Possibly vulnerable |
| Below 0.70 | Low | Filtered out by default |

#### False Positive Prevention

- **Encoding Detection**: HTML entities indicate safe output
- **Response Size Comparison**: Requires >100 byte difference for significant changes
- **Database-Specific Patterns**: Only matches known database error messages
- **Pattern Specificity**: Avoids generic "error" matches
- **Multi-Stage Confirmation**: Re-tests findings with payload variations

---

## Payload System

### Payload Registry (`scanner/payloads/registry.py`)

Central registry managing 67+ payloads across 10 vulnerability types.

#### Supported Vulnerability Types

| Type | File | Count | Description |
|------|------|-------|-------------|
| **XSS** | xss.py | 16 | Reflected, DOM-based, event handlers, tag injection |
| **SQL Injection** | sqli.py | 18 | Error-based, boolean-based, union-based, time-based |
| **NoSQL Injection** | nosql.py | 12+ | MongoDB operators, authentication bypass |
| **Path Traversal** | traversal.py | 20 | Directory traversal with encoding bypasses |
| **Open Redirect** | redirect.py | 8 | Protocol-relative, backslash, double-slash |
| **Header Injection** | header_injection.py | 5 | CRLF injection, response splitting |
| **SSTI** | ssti.py | 8+ | Jinja2, Twig, FreeMarker, Velocity, Mako |
| **XXE** | xxe.py | 5+ | File disclosure, SSRF via XXE |
| **Command Injection** | command_injection.py | 10+ | Unix/Windows commands, time-based |
| **SSRF** | ssrf.py | 15+ | Localhost, metadata, internal network |

#### Payload Structure

```python
@dataclass
class Payload:
    vuln_type: str              # e.g., "XSS"
    name: str                   # e.g., "Script Tag Injection"
    payload: str                # The actual payload string
    contexts: List[str]         # ["url", "form", "header", "json"]
    severity: str               # "Low" / "Medium" / "High" / "Critical"
    safe: bool                  # Ethical testing flag
    confirmation: Callable      # Response analyzer function
```

#### Example Payloads

**XSS (Cross-Site Scripting)**
```python
Payload(
    vuln_type="XSS",
    name="Script Tag Basic",
    payload="<script>alert('XSS')</script>",
    contexts=["url", "form"],
    severity="High",
    safe=True,
    confirmation=lambda r: "<script>alert('XSS')</script>" in r
)
```

**SQL Injection**
```python
Payload(
    vuln_type="SQLi",
    name="Error-Based Single Quote",
    payload="'",
    contexts=["url", "form"],
    severity="Critical",
    safe=True,
    confirmation=lambda r: any(err in r.lower() for err in [
        "sql syntax", "mysql", "postgresql", "sqlite"
    ])
)
```

#### Injection Points

Payloads are tested in multiple contexts:

1. **URL Parameters** (GET requests)
2. **Form Data** (POST requests)
3. **JSON Body** (API requests)
4. **HTTP Headers** (Cookie, User-Agent, etc.)
5. **XML Body** (for XXE testing)

---

## Database Schema

### Tables Overview

```sql
-- Users table
CREATE TABLE Users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    role_level INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- Sessions table
CREATE TABLE Sessions (
    session_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES Users(user_id)
);

-- Scans table
CREATE TABLE Scans (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    target_url TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    findings_count INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES Users(user_id)
);

-- Forms table
CREATE TABLE Forms (
    form_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    page_url TEXT NOT NULL,
    method TEXT,
    action TEXT,
    inputs TEXT,
    FOREIGN KEY (scan_id) REFERENCES Scans(scan_id)
);

-- Vulnerabilities table
CREATE TABLE Vulnerabilities (
    vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    form_id INTEGER,
    vuln_type TEXT NOT NULL,
    severity TEXT CHECK(severity IN ('low', 'medium', 'high', 'critical')),
    payload_used TEXT,
    evidence TEXT,
    confidence REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES Scans(scan_id),
    FOREIGN KEY (form_id) REFERENCES Forms(form_id)
);

-- Reports table
CREATE TABLE Reports (
    report_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    scan_id INTEGER NOT NULL,
    summary TEXT,
    total_vulns INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES Users(user_id),
    FOREIGN KEY (scan_id) REFERENCES Scans(scan_id)
);

-- Logs table
CREATE TABLE Logs (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    level TEXT,
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES Scans(scan_id)
);
```

### Role-Based Access Control

| Role | Permissions |
|------|-------------|
| **admin** | read_all, write_all, delete, create_scan, view_reports, manage_users |
| **security_officer** | read_all, create_scan, view_reports |
| **user** | create_scan, view_own, view_reports |
| **readonly** | read_all |

---

## API Reference

### Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/login` | Login with username/password | No |
| POST | `/register` | Create new user account | No |
| POST | `/logout` | Invalidate current session | Yes |
| POST | `/refresh` | Refresh token (extend expiry) | Yes |
| GET | `/verify` | Verify token validity | No |

#### Login Request/Response

```json
// POST /login
// Request
{
    "username": "admin",
    "password": "Admin@123"
}

// Response
{
    "token": "abc123...",
    "user_id": 1,
    "username": "admin",
    "role": "admin"
}
```

### Scanning Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/scan/` | Start a new scan | Yes |
| GET | `/scan/{job_id}` | Get scan results | Yes |
| GET | `/scan/{job_id}/progress` | Get real-time progress | Yes |
| GET | `/scan/{job_id}/logs` | Get scan logs | Yes |
| GET | `/scan/{job_id}/vulnerabilities` | Get found vulnerabilities | Yes |

#### Start Scan Request/Response

```json
// POST /scan/?url=https://example.com&max_pages=30
// Response
{
    "job_id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "pending",
    "message": "Scan queued successfully"
}
```

#### Progress Response

```json
// GET /scan/{job_id}/progress
{
    "status": "running",
    "phase": "testing",
    "current_url": "https://example.com/login",
    "visited_count": 15,
    "total_forms": 8,
    "findings_count": 3,
    "start_time": "2024-01-15T10:30:00Z"
}
```

### Report Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/reports/` | List user's reports | Yes |
| GET | `/reports/{id}` | Get report details | Yes |
| POST | `/reports/generate/{scan_id}` | Generate report | Yes |
| GET | `/reports/download/{id}` | Download report file | Yes |
| GET | `/reports/view/{id}` | View HTML report | Yes |

---

## Frontend UI

### Pages

#### Login Page (`Login.tsx`)
- Username and password form
- Posts credentials to `/login`
- Stores token in localStorage
- Redirects to dashboard on success

#### Register Page (`Register.tsx`)
- Registration form with validation
- Email validation
- Password confirmation
- Password requirements enforcement

#### Dashboard (`Dashboard.tsx`)
- Statistics cards (Total, Active, Completed, Failed scans)
- Quick action buttons
- Recent scans table with status badges
- Finding counts display

#### New Scan Page (`NewScan.tsx`)
- URL input field
- Max pages configuration slider
- Optional target authentication
- Real-time progress display
- Phase indicators (Crawling/Testing/Complete)
- Live log viewer
- Results table with vulnerability details

#### Reports Page (`Reports.tsx`)
- Report list view
- Generate report buttons
- Download/view options
- Filtering capabilities

### API Client (`api/client.ts`)

```typescript
const API_BASE = "http://localhost:8000";

export function getToken(): string | null {
    return localStorage.getItem("token");
}

export async function apiFetch(endpoint: string, options: RequestInit = {}) {
    const token = getToken();
    const headers = {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...options.headers,
    };

    const response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers,
    });

    return response;
}
```

### Styling

The UI uses a dark theme with:
- CSS custom properties for colors
- Responsive grid layouts
- Status badges with severity colors
- Consistent spacing and typography

---

## Authentication System

### Flow

```
1. User Registration
   └── Password validated (8+ chars, upper, lower, digit, special)
   └── Password hashed with bcrypt
   └── User created with 'user' role

2. User Login
   └── Username/password submitted
   └── Password verified against hash
   └── Session token generated (UUID)
   └── Token stored in Sessions table (24hr expiry)
   └── Token returned to client

3. Authenticated Requests
   └── Token sent in Authorization header
   └── Middleware validates token
   └── User info attached to request
   └── Endpoint processes request

4. Token Refresh
   └── Client calls /refresh before expiry
   └── New token generated with extended expiry
   └── Old token invalidated
```

### Security Features

- **Password Hashing**: bcrypt with automatic salt
- **Token Expiry**: 24-hour session lifetime
- **Session Rotation**: New token on refresh
- **Server-Side Storage**: Tokens stored in database
- **Role-Based Access**: Permissions checked per endpoint

---

## Report Generation

### Process

1. Fetch scan data from database
2. Retrieve all vulnerabilities for scan
3. Group vulnerabilities by severity
4. Calculate risk score (0-100)
5. Render Jinja2 HTML template
6. Convert to PDF (if WeasyPrint available)
7. Save to `/reports/` directory

### Report Contents

- **Executive Summary**: Overview of findings
- **Risk Score**: Calculated from severity distribution
- **Vulnerability Breakdown**: Grouped by type and severity
- **Detailed Findings**:
  - URL and parameter affected
  - Payload used
  - Evidence captured
  - Confidence score
  - Remediation suggestions
- **Scan Metadata**: Target, timing, coverage

### Risk Score Calculation

```python
def calculate_risk_score(vulnerabilities):
    weights = {
        'critical': 40,
        'high': 25,
        'medium': 10,
        'low': 5
    }

    score = sum(weights.get(v.severity, 0) for v in vulnerabilities)
    return min(score, 100)  # Cap at 100
```

---

## Task Queue & Workers

### Job Lifecycle

```
1. Job Created
   └── UUID generated
   └── Database record created (status: pending)
   └── Added to in-memory queue

2. Worker Processing
   └── Worker picks up job
   └── Status updated to 'running'
   └── Crawler executes
   └── Vulnerability testing runs
   └── Progress updated in real-time

3. Completion
   └── Results saved to database
   └── Status updated to 'completed' or 'failed'
   └── Job removed from queue
```

### Configuration

```python
MAX_CONCURRENT_SCANS = 2       # Parallel scans
MAX_RETRIES = 2                # Retry attempts (3 total)
JOB_TIMEOUT_SECONDS = 600      # 10-minute timeout
WATCHDOG_INTERVAL = 10         # Check interval (seconds)
```

### Retry Logic

```python
# Exponential backoff
delay = 3 * (2 ** (attempt - 1))
# Attempt 1: 3 seconds
# Attempt 2: 6 seconds
# Attempt 3: 12 seconds
```

### Watchdog Thread

- Runs every 10 seconds
- Checks for jobs exceeding timeout
- Marks stuck jobs as failed
- Logs timeout events

### Startup Recovery

On application startup:
- Finds scans with status 'running'
- Marks them as 'failed'
- Logs recovery action

---

## Configuration

### Scanner Configuration

```python
SCANNER_CONFIG = {
    'min_confidence': 0.7,          # Minimum confidence threshold
    'confirm_findings': True,        # Enable multi-stage confirmation
    'timeout': 15,                   # Request timeout (seconds)
    'max_retries': 3,                # Retries per request
    'delay_between_requests': 0.1,   # Delay between requests
}
```

### Crawler Configuration

```python
CRAWLER_CONFIG = {
    'max_pages': 30,           # Maximum pages to crawl
    'max_depth': 5,            # Maximum link depth
    'timeout': 30000,          # Page load timeout (ms)
    'wait_for_idle': True,     # Wait for network idle
    'click_discovery': True,   # Click for discovery
    'scroll_discovery': True,  # Scroll for lazy loading
    'js_extraction': True,     # Extract URLs from JS
}
```

### Database Configuration

```python
DB_NAME = 'web_scanner.db'     # Database file name
# Can be overridden with WEB_SCANNER_DB environment variable
```

### CORS Configuration

```python
CORS_CONFIG = {
    'allow_origins': ['http://localhost:5173'],
    'allow_credentials': True,
    'allow_methods': ['*'],
    'allow_headers': ['*'],
}
```

---

## Scanning Flow

### End-to-End Process

```
┌─────────────────────────────────────────────────────────────────┐
│                      SCAN INITIATION                             │
├─────────────────────────────────────────────────────────────────┤
│  1. User submits URL via UI                                     │
│  2. POST /scan/?url=https://target.com&max_pages=30             │
│  3. Authentication middleware validates token                    │
│  4. Job created with UUID, added to queue                       │
│  5. Returns job_id for polling                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      CRAWLING PHASE                              │
├─────────────────────────────────────────────────────────────────┤
│  1. Worker picks up job from queue                              │
│  2. Playwright browser launches                                 │
│  3. Visits target URL, renders JavaScript                       │
│  4. Discovers pages via 10+ techniques                          │
│  5. Extracts forms, links, API endpoints                        │
│  6. Updates progress: phase="crawling"                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      TESTING PHASE                               │
├─────────────────────────────────────────────────────────────────┤
│  1. Iterates through discovered forms/endpoints                 │
│  2. Tests each with relevant payloads                           │
│  3. Analyzes responses for vulnerabilities                      │
│  4. Confirms findings with multi-stage tests                    │
│  5. Assigns confidence scores                                   │
│  6. Updates progress: phase="testing"                           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      COMPLETION                                  │
├─────────────────────────────────────────────────────────────────┤
│  1. All findings saved to Vulnerabilities table                 │
│  2. Scan status updated to 'completed'                          │
│  3. Findings count updated                                      │
│  4. Frontend displays results                                   │
│  5. User can generate report                                    │
└─────────────────────────────────────────────────────────────────┘
```

### Frontend Polling

```typescript
// Poll for progress every 2 seconds
const pollProgress = async (jobId: string) => {
    const response = await apiFetch(`/scan/${jobId}/progress`);
    const data = await response.json();

    if (data.status === 'completed') {
        // Fetch final results
        const results = await apiFetch(`/scan/${jobId}`);
        setResults(await results.json());
    } else if (data.status === 'failed') {
        setError('Scan failed');
    } else {
        // Update progress UI
        setProgress(data);
        setTimeout(() => pollProgress(jobId), 2000);
    }
};
```

---

## Summary

This web vulnerability scanner provides:

- **Comprehensive Crawling**: 10+ discovery techniques with JavaScript rendering
- **Extensive Testing**: 67+ payloads across 10 vulnerability types
- **High Accuracy**: Multi-stage confirmation with confidence scoring
- **User Management**: Multi-user support with role-based access
- **Real-Time Monitoring**: Live progress updates during scans
- **Professional Reports**: HTML/PDF reports with detailed findings
- **Resilient Operation**: Retry logic, timeouts, and recovery mechanisms

The modular architecture allows for easy extension of payload types, detection methods, and reporting formats.
