# 🛡️ Web Vulnerability Scanner

A comprehensive web application security scanner built with Python (FastAPI) and React (TypeScript). This tool crawls websites, discovers forms and URL parameters, and tests them for common vulnerabilities including XSS, SQL Injection, Path Traversal, Open Redirects, and Header Injection.

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Running the Application](#-running-the-application)
- [Usage Guide](#-usage-guide)
- [API Documentation](#-api-documentation)
- [Project Structure](#-project-structure)
- [Security Considerations](#-security-considerations)
- [Troubleshooting](#-troubleshooting)

---

## ✨ Features

### Scanning Capabilities
- **Intelligent Crawling**: Uses Playwright for JavaScript-rendered content discovery
- **Form Detection**: Automatically discovers and extracts HTML forms with their parameters
- **URL Parameter Extraction**: Identifies injectable parameters from URLs
- **Authenticated Scanning**: Supports login to scan protected areas

### Vulnerability Detection
| Type | Payloads | Description |
|------|----------|-------------|
| **XSS** | 16 | Cross-Site Scripting (reflected, DOM-based) |
| **SQL Injection** | 18 | Error-based, boolean-based, union-based |
| **Path Traversal** | 20 | Directory traversal attacks |
| **Open Redirect** | 8 | URL redirection vulnerabilities |
| **Header Injection** | 5 | CRLF injection attacks |

### Additional Features
- 🔐 User authentication with role-based access control
- 📊 Real-time scan progress tracking
- 📝 Detailed vulnerability reports
- 💾 SQLite database for persistent storage
- 🎨 Modern dark-themed React UI

---

## 🏗️ Architecture

```
┌─────────────────┐         ┌─────────────────┐
│                 │   API   │                 │
│   React UI      │◄───────►│   FastAPI       │
│   (Frontend)    │         │   (Backend)     │
│                 │         │                 │
└─────────────────┘         └────────┬────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                │
              ┌─────▼─────┐   ┌──────▼──────┐  ┌─────▼─────┐
              │           │   │             │  │           │
              │  Crawler  │   │  Vuln       │  │  SQLite   │
              │ (Playwright)│   │  Tester     │  │  Database │
              │           │   │             │  │           │
              └───────────┘   └─────────────┘  └───────────┘
```

---

## 📦 Prerequisites

### Required Software
- **Python** 3.10 or higher
- **Node.js** 18 or higher
- **npm** 9 or higher

### Python Dependencies
```
fastapi
uvicorn
playwright
requests
passlib[bcrypt]
python-multipart
```

### Node Dependencies
```
react
react-router-dom
typescript
vite
```

---

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd web-scanner
```

### 2. Backend Setup
```bash
# Navigate to backend directory
cd app

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install Python dependencies
pip install fastapi uvicorn playwright requests passlib[bcrypt] python-multipart

# Install Playwright browsers
playwright install chromium

# Initialize the database
python -m db.database
```

### 3. Frontend Setup
```bash
# Navigate to frontend directory
cd web-scanner-ui

# Install Node dependencies
npm install
```

---

## ▶️ Running the Application

### Start the Backend Server
```bash
# From the app/ directory
uvicorn main:app --reload
```
The API will be available at: `http://localhost:8000`

### Start the Frontend Development Server
```bash
# From the web-scanner-ui/ directory
npm run dev
```
The UI will be available at: `http://localhost:5173`

### Default Login Credentials
```
Username: admin
Password: admin123
```
⚠️ **Change these credentials immediately in production!**

---

## 📖 Usage Guide

### Starting a New Scan

1. **Login** to the application
2. Navigate to **New Scan** from the sidebar
3. Enter the **Target URL** (e.g., `https://example.com`)
4. Set **Max Pages** to crawl (default: 10)
5. *(Optional)* Configure **Target Authentication** if the site requires login
6. Click **Start Scan**

### Understanding Scan Phases

| Phase | Description |
|-------|-------------|
| 🕷️ **Crawling** | Discovering pages, forms, and URL parameters |
| 🔬 **Testing** | Sending payloads to detected injection points |
| ✅ **Complete** | Results ready for review |

### Interpreting Results

**Severity Levels:**
- 🔴 **Critical**: Immediate action required
- 🟠 **High**: Serious vulnerability
- 🟡 **Medium**: Moderate risk
- 🟢 **Low**: Minor concern

---

## 🔌 API Documentation

### Authentication

#### Login
```http
POST /login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin123"
}
```

#### Register
```http
POST /register
Content-Type: application/json

{
  "username": "newuser",
  "email": "user@example.com",
  "password": "securepass",
  "confirm_password": "securepass"
}
```

### Scanning

#### Start Scan
```http
POST /scan/?url=https://example.com&max_pages=10
Authorization: Bearer <token>
```

#### Get Progress
```http
GET /scan/{job_id}/progress
Authorization: Bearer <token>
```

#### Get Logs
```http
GET /scan/{job_id}/logs
Authorization: Bearer <token>
```

### Reports

#### List Scans
```http
GET /scans
Authorization: Bearer <token>
```

#### Get Vulnerabilities
```http
GET /scans/{scan_id}/vulnerabilities
Authorization: Bearer <token>
```

---

## 📁 Project Structure

```
web-scanner/
├── app/                          # Backend (Python/FastAPI)
│   ├── main.py                   # FastAPI application entry point
│   ├── db/
│   │   ├── database.py           # Database models and functions
│   │   └── db_utils.py           # Database utilities
│   └── scanner/
│       ├── engine.py             # Core scanning engine
│       ├── vulnerability_tester.py # Vulnerability testing logic
│       ├── http_client.py        # HTTP request utilities
│       ├── task_queue.py         # Background job management
│       ├── extractor.py          # Form/link extraction
│       ├── scope.py              # URL scope checking
│       ├── models.py             # Data models
│       ├── auth_manager.py       # Target authentication
│       └── payloads/
│           ├── registry.py       # Payload management
│           ├── xss.py            # XSS payloads
│           ├── sqli.py           # SQL Injection payloads
│           ├── traversal.py      # Path Traversal payloads
│           ├── redirect.py       # Open Redirect payloads
│           └── header_injection.py # Header Injection payloads
│
├── web-scanner-ui/               # Frontend (React/TypeScript)
│   ├── src/
│   │   ├── App.tsx               # Main application component
│   │   ├── index.css             # Global styles (dark theme)
│   │   ├── api/
│   │   │   └── client.ts         # API client configuration
│   │   ├── pages/
│   │   │   ├── Login.tsx         # Login page
│   │   │   ├── Register.tsx      # Registration page
│   │   │   ├── Dashboard.tsx     # Dashboard page
│   │   │   └── NewScan.tsx       # Scan configuration page
│   │   └── components/
│   │       └── Sidebar.tsx       # Navigation sidebar
│   ├── package.json
│   └── vite.config.ts
│
├── web_scanner.db                # SQLite database (created on first run)
└── README.md                     # This file
```

---

## 🔒 Security Considerations

### ⚠️ Important Warnings

1. **Authorization Required**: Only scan websites you own or have explicit permission to test
2. **Legal Compliance**: Unauthorized scanning may violate computer crime laws
3. **Network Impact**: Scanning can generate significant traffic and may trigger security alerts
4. **Production Use**: Change default credentials and use HTTPS in production

### Best Practices

- Run scans during off-peak hours
- Start with low `max_pages` values
- Review target's terms of service
- Keep scan logs for accountability
- Use rate limiting for external targets

---

## 🔧 Troubleshooting

### Common Issues

#### "Database is locked" Error
```bash
# The scanner handles this automatically with retries
# If persistent, restart the backend server
```

#### Scan Never Completes
- Check if the target is accessible
- Reduce `max_pages` value
- Check backend logs for errors

#### SSL Certificate Warnings
```
# These are suppressed by default for testing
# The scanner can test sites with self-signed certificates
```

#### Playwright Browser Not Found
```bash
# Reinstall Playwright browsers
playwright install chromium
```

### Getting Help

1. Check the backend console for error messages
2. View scan logs via the UI "Show Logs" button
3. Check browser developer console for frontend errors

---

## 📄 License

This project is for educational and authorized security testing purposes only.

---

## 👥 Authors

Developed as a web security scanning project.

---

## 🙏 Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [Playwright](https://playwright.dev/) - Browser automation
- [React](https://react.dev/) - UI framework
- [OWASP](https://owasp.org/) - Security testing methodologies