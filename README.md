# Web Vulnerability Scanner

A full-stack DAST (dynamic application security testing) tool that crawls a target site with a real browser, fingerprints injection points, and tests them against a payload library spanning 10+ vulnerability classes. Built end-to-end: browser automation, async job queue, REST API, authenticated SPA, PDF/HTML reporting.

> **Authorized testing only.** Run this against systems you own or have written permission to test.

---

## Table of Contents

- [Highlights](#highlights)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Vulnerability Coverage](#vulnerability-coverage)
- [Quick Start](#quick-start)
- [Project Layout](#project-layout)
- [API Surface](#api-surface)
- [Engineering Notes](#engineering-notes)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [License & Disclaimer](#license--disclaimer)

---

## Highlights

- **Headless-browser crawler** built on Playwright — captures network requests, executes JavaScript, follows SPA routes, parses sitemaps, and harvests URLs from JS source via regex extraction.
- **Background job queue** with watchdog timeouts, exponential-backoff retries, startup recovery for stuck scans, and per-scan persisted log streams.
- **10+ vulnerability classes** in a pluggable payload registry (XSS, SQLi, NoSQLi, SSTI, XXE, command injection, SSRF, path traversal, open redirect, header injection).
- **Confidence scoring & confirmation passes** to suppress false positives — error-pattern matching, baseline diffing, and timing-based corroboration.
- **Authenticated scanning** — drive a target login flow with a session manager, then scan protected areas with the captured cookies.
- **Role-based authentication** — bcrypt-hashed credentials, server-side bearer-token sessions, refresh + logout, and middleware that gates every route.
- **HTML & PDF reports** — Jinja2-rendered findings with severity grouping, risk score, payload, evidence, and remediation hints.
- **DFS vulnerability graph** — interactive React + SVG visualisation of the scanned crawl graph, exploitable paths, and clusters.

> Screenshots: `docs/screenshots/` (add your own captures of the dashboard, scan view, and reports).

---

## Tech Stack

| Layer            | Technology                                       |
| ---------------- | ------------------------------------------------ |
| Backend          | Python 3.10+, FastAPI, Uvicorn                   |
| Crawler          | Playwright (Chromium)                            |
| HTTP testing     | `requests`, `urllib3`                            |
| Database         | SQLite (WAL-friendly schema, FK constraints on)  |
| Auth             | bcrypt (passlib), opaque bearer tokens           |
| Frontend         | React 18, TypeScript, Vite, React Router         |
| Reports          | Jinja2 templates, WeasyPrint / pdfkit (PDF)      |
| Tests            | pytest + FastAPI TestClient, Vitest + RTL (UI)   |

---

## Architecture

```
┌────────────────┐        ┌─────────────────────────────────────────────┐
│  React SPA     │  REST  │  FastAPI                                    │
│  (Vite + TS)   │ ─────► │  ├─ auth router    (login/register/refresh) │
│                │        │  ├─ scans router   (start/progress/logs)    │
│  • Dashboard   │ ◄───── │  ├─ reports router (HTML / PDF)             │
│  • New Scan    │  JSON  │  └─ auth middleware (Bearer + RBAC)         │
│  • Reports     │        └──────────────┬──────────────────────────────┘
│  • Vuln Graph  │                       │
└────────────────┘                       ▼
                              ┌──────────────────────┐
                              │ Job queue + worker   │
                              │ (thread + watchdog)  │
                              └─────────┬────────────┘
                                        │
                ┌───────────────────────┼───────────────────────┐
                ▼                       ▼                       ▼
        ┌──────────────┐       ┌────────────────┐      ┌──────────────┐
        │ Playwright   │       │ Vulnerability  │      │ SQLite       │
        │ Crawler      │  ───► │ Tester         │ ───► │ (scans,      │
        │ (forms,      │       │ (10+ payload   │      │  forms,      │
        │ links, JS,   │       │  families,     │      │  vulns,      │
        │ SPA routes)  │       │  confidence    │      │  logs,       │
        │              │       │  scoring)      │      │  reports)    │
        └──────────────┘       └────────────────┘      └──────────────┘
```

Request lifecycle:

1. UI submits a scan → router validates URL (SSRF guard) and enqueues a job.
2. Background worker pulls the job, drives Playwright, persists discovered forms/URLs.
3. The vulnerability tester walks each injection point, sends payloads, and scores responses.
4. Findings stream into SQLite; the UI polls progress/logs every 2s and renders results.
5. The user generates an HTML/PDF report from any completed scan.

---

## Vulnerability Coverage

| Class               | Payloads | Detection technique                                  |
| ------------------- | :------: | ---------------------------------------------------- |
| XSS                 | 16       | Reflection match, context-aware (HTML/attr/JS)       |
| SQL Injection       | 18       | Error-string fingerprint, boolean diff, time-based   |
| NoSQL Injection     | 12+      | Operator injection, boolean diff                     |
| SSTI                | 8+       | Engine-specific markers (Jinja2/Twig/Velocity/Mako)  |
| XXE                 | 5+       | File-disclosure markers                              |
| Command Injection   | 10+      | Output marker + time-based corroboration             |
| SSRF                | 15+      | Status / banner indicators                           |
| Path Traversal      | 20       | `/etc/passwd`, Windows path, encoding bypasses       |
| Open Redirect       | 8        | Location header, double-slash, protocol-relative     |
| Header Injection    | 5        | CRLF, response splitting                             |

Each finding records the payload, the response evidence, the matched indicators, a confidence score (0.0–1.0), and a severity tier.

---

## Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+
- A target you own or are authorized to scan

### Backend

```bash
cd app
python -m venv .venv
source .venv/bin/activate          # PowerShell: .venv\Scripts\Activate.ps1
pip install -r ../requirements.txt # or: pip install fastapi uvicorn playwright requests passlib[bcrypt] python-multipart jinja2
playwright install chromium
uvicorn main:app --reload --port 8000
```

The API is served at `http://localhost:8000` (Swagger UI at `/docs`).

### Frontend

```bash
cd web-scanner-ui
cp .env.example .env       # then edit VITE_API_URL if not localhost:8000
npm install
npm run dev
```

UI at `http://localhost:5173`.

### First login

The backend bootstraps an admin account on first start. Set
`WEB_SCANNER_ADMIN_PASSWORD` (and optionally `WEB_SCANNER_ADMIN_USERNAME` / `..._EMAIL`)
before launching — the server refuses to start without one. For a throwaway dev
instance you can set `WEB_SCANNER_DEV=1` to use the insecure default
`admin / Admin@123`; never do this in production.

### Environment variables

| Variable                        | Where    | Purpose                                                       |
| ------------------------------- | -------- | ------------------------------------------------------------- |
| `WEB_SCANNER_DB`                | backend  | Override SQLite path (used by tests too)                      |
| `WEB_SCANNER_ADMIN_PASSWORD`    | backend  | Required to bootstrap the first admin (or set `WEB_SCANNER_DEV=1` for the insecure dev default) |
| `WEB_SCANNER_ADMIN_USERNAME`    | backend  | Override default admin username (`admin`)                     |
| `WEB_SCANNER_ADMIN_EMAIL`       | backend  | Override default admin email                                  |
| `WEB_SCANNER_DEV`               | backend  | Set to `1` to allow the insecure default admin password (dev only) |
| `ALLOWED_ORIGINS`               | backend  | Comma-separated CORS allowlist (default: localhost:5173)      |
| `VITE_API_URL`                  | frontend | API base URL for the SPA                                      |

---

## Project Layout

```
web-scanner/
├── app/                              # FastAPI backend
│   ├── main.py                       # ASGI entry, lifespan, CORS, middleware
│   ├── api/auth/{login,register}.py  # Auth endpoints
│   ├── security/middleware.py        # Bearer-token middleware + public allowlist
│   ├── db/{database,db_utils,backup}.py
│   ├── scans/scans_router.py         # Start / progress / logs / vulns / graph
│   ├── reports/{generator,reports_router,remediation}.py
│   └── scanner/
│       ├── engine.py                 # Playwright crawler
│       ├── vulnerability_tester.py   # Payload runner + confidence scoring
│       ├── task_queue.py             # Job queue + watchdog + retries
│       ├── worker.py                 # Background worker thread
│       ├── extractor.py              # Form / link / JS-URL extraction
│       ├── scope.py                  # In-scope URL filter
│       ├── http_client.py            # Per-target HTTP helpers
│       ├── auth_manager.py           # Target login flows
│       ├── graph_analyzer.py         # DFS / cycle / cluster analysis
│       └── payloads/                 # One module per vuln class
├── web-scanner-ui/                   # React + TypeScript SPA
│   └── src/
│       ├── api/client.ts             # apiFetch + token handling
│       ├── components/{Sidebar,VulnerabilityGraph}.tsx
│       └── pages/{Login,Register,Dashboard,NewScan,Reports}.tsx
├── tests/                            # pytest suites (unit + integration)
├── reports/                          # Generated HTML/PDF (gitignored)
├── pytest.ini
└── README.md
```

---

## API Surface

| Method | Path                              | Description                                |
| ------ | --------------------------------- | ------------------------------------------ |
| POST   | `/login`                          | Username/password → bearer token           |
| POST   | `/register`                       | Create user                                |
| POST   | `/refresh`                        | Rotate token                               |
| POST   | `/logout`                         | Revoke token                               |
| GET    | `/verify`                         | Token introspection                        |
| GET    | `/scan/list`                      | List scans (RBAC-filtered)                 |
| POST   | `/scan/`                          | Start scan (JSON body, URL-validated, SSRF-guarded) |
| GET    | `/scan/{job_id}`                  | Final result                               |
| GET    | `/scan/{job_id}/progress`         | Real-time progress                         |
| GET    | `/scan/{job_id}/logs`             | Persisted log stream                       |
| GET    | `/scan/{job_id}/vulnerabilities`  | Findings detail                            |
| GET    | `/scan/{job_id}/graph`            | DFS graph payload (nodes / edges / cycles) |
| GET    | `/reports/`                       | List reports                               |
| POST   | `/reports/generate/{scan_id}`     | Render HTML + PDF                          |
| GET    | `/reports/view/{report_id}`       | Inline HTML                                |
| GET    | `/reports/download/{report_id}`   | Download file                              |

Full schema is browsable at `/docs` (Swagger) and `/redoc` once the backend is running.

---

## Engineering Notes

- **SSRF defense** — `/scan/` resolves the target host and rejects any address that lands in loopback / private / link-local / multicast / reserved space, plus blocks well-known metadata hostnames. Proxy URLs are restricted to `http(s)`.
- **Credentials never in URLs** — scan-target credentials are accepted only via the JSON body; the JWT for report download/view is sent in the `Authorization` header (the SPA fetches the file as a Blob and serves it locally), so tokens never appear in browser history, referer chains, or access logs.
- **Cooperative cancellation** — the watchdog flips a `threading.Event` before failing a stuck job; the crawler checks it between pages and the tester between targets, so Playwright shuts down cleanly instead of leaking a browser process.
- **Thread-safe payload runner** — the vulnerability tester's parallel mode uses a per-thread `requests.Session` (via `threading.local`); no shared state is mutated from multiple workers.
- **Bcrypt-only password storage** — the legacy SHA-256 fallback path is removed; missing `passlib[bcrypt]` is a hard startup failure.
- **No leaked stack traces** — `5xx` responses return generic messages; the full exception is logged server-side.
- **Resilience** — startup recovery walks `Scans` for `running` rows and marks them `failed`; new scans then start from a clean state. Finished jobs are pruned from the in-memory map after a TTL so the queue map can't grow forever.
- **Payload registry** is `dataclass`-driven — adding a new vuln class is a single file with `Payload(...)` entries plus a `confirmation` callable; nothing else changes.
- **Confidence scoring** uses signal compounding: encoding detection, baseline-size delta, DB-specific error patterns, and confirmation re-tests with payload variations.

---

## Testing

```bash
# Backend (in app/ venv, from repo root)
pytest

# Frontend
cd web-scanner-ui
npm run test:run
```

Backend tests use `WEB_SCANNER_DB` to point at a per-test SQLite path and `FastAPI TestClient` for integration coverage of the full scan flow. Frontend tests run in jsdom via Vitest + Testing Library.

---

## Roadmap

- [ ] Persist queue/state to Redis so scans survive restarts and scale horizontally.
- [ ] OWASP ZAP-compatible report export.
- [ ] Per-target rate-limiting & politeness controls.
- [ ] Authenticated-scan flows beyond cookie capture (OAuth, SSO).
- [ ] CI workflow (GitHub Actions) running `pytest` + `npm run test:run` on PRs.

---

## License & Disclaimer

Released for **educational and authorized security-testing purposes only.** Unauthorized scanning may violate computer-misuse laws in your jurisdiction. You are responsible for obtaining permission before pointing this tool at any system you do not own.
