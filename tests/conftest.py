import os
import sys
import importlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


# Ensure project root, app/, and app/api/auth/ are importable so tests can do
# `import db.database`, `import scanner.engine`, and `import register` /
# `import login` without depending on $PYTHONPATH or rootdir quirks.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_DIR = PROJECT_ROOT / "app"
AUTH_DIR = APP_DIR / "api" / "auth"
for path in (PROJECT_ROOT, APP_DIR, AUTH_DIR):
    p = str(path)
    if p not in sys.path:
        sys.path.insert(0, p)


@pytest.fixture()
def temp_db(tmp_path: Path, monkeypatch):
    """Create an isolated sqlite DB per test run."""
    db_path = tmp_path / "test_web_scanner.db"

    # Must set env BEFORE importing database/login/register modules
    monkeypatch.setenv("WEB_SCANNER_DB", str(db_path))
    # Allow ensure_admin_exists() to bootstrap a default admin in tests without
    # requiring a real WEB_SCANNER_ADMIN_PASSWORD value.
    monkeypatch.setenv("WEB_SCANNER_DEV", "1")

    import db.database as database
    importlib.reload(database)

    database.init_database()

    return db_path


@pytest.fixture()
def register_client(temp_db):
    import register
    importlib.reload(register)
    return TestClient(register.app)


@pytest.fixture()
def login_client(temp_db):
    import login
    importlib.reload(login)
    return TestClient(login.app)


@pytest.fixture()
def db_module(temp_db):
    import db.database as database
    importlib.reload(database)
    return database

@pytest.fixture()
def app_client(temp_db, monkeypatch):
    """
    TestClient for the full FastAPI app (app/main.py) in Route A style.
    Uses the same temp DB set by temp_db fixture via WEB_SCANNER_DB.

    The ``with`` block enters the lifespan context so that ``start_worker()``
    is called before tests run and the background scanner thread is alive for
    the duration of each test.
    """
    import main
    importlib.reload(main)
    with TestClient(main.app) as client:
        yield client


@pytest.fixture(autouse=True)
def fake_webscanner(monkeypatch):
    """
    Speed up integration tests by replacing the Playwright-based scanner with a fake.
    This keeps tests deterministic and fast (no browser/network dependency).
    """
    class FakeWebScanner:
        def __init__(self, url, max_pages, cookies=None, db_scan_id=None, job_id=None, callback=None, proxy=None, **kwargs):
            self.url = url
            self.max_pages = max_pages
            self.cookies = cookies
            self.db_scan_id = db_scan_id
            self.job_id = job_id
            self.callback = callback

        def scan(self):
            if self.callback:
                self.callback(self.job_id, {"current_url": self.url, "visited_count": 1})
                self.callback(self.job_id, {"new_target": {"url": self.url, "issue": "demo"}})
            return {
                "targets": [{"url": self.url, "method": "GET", "parameters": ["q"], "context": "url"}],
                "findings": [{"url": self.url, "type": "XSS", "severity": "high", "parameter": "q", "payload": "<script>alert(1)</script>"}],
                "api_endpoints": [],
                "discovered_urls": [self.url],
                "network_urls": [],
                "stats": {
                    "pages_visited": 1,
                    "pages_discovered": 1,
                    "forms_found": 0,
                    "targets_found": 1,
                    "api_endpoints_found": 0,
                    "network_requests_captured": 0,
                    "elements_clicked": 0,
                    "vulnerabilities_found": 1,
                    "errors": 0,
                },
                "crawl_graph": {
                    "visited_urls": [self.url],
                    "page_links": {self.url: []},
                    "page_depths": {self.url: 0},
                    "page_parents": {},
                },
            }

    # Route A import path
    import scanner.engine as engine
    monkeypatch.setattr(engine, "WebScanner", FakeWebScanner)
