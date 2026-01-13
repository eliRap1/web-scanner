import os
import sys
import importlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


# Ensure project root is importable when pytest runs with different import modes.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture()
def temp_db(tmp_path: Path, monkeypatch):
    """Create an isolated sqlite DB per test run."""
    db_path = tmp_path / "test_web_scanner.db"

    # Must set env BEFORE importing database/login/register modules
    monkeypatch.setenv("WEB_SCANNER_DB", str(db_path))

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
    """
    import main
    importlib.reload(main)
    return TestClient(main.app)


@pytest.fixture(autouse=True)
def fake_webscanner(monkeypatch):
    """
    Speed up integration tests by replacing the Playwright-based scanner with a fake.
    This keeps tests deterministic and fast (no browser/network dependency).
    """
    class FakeWebScanner:
        def __init__(self, url, max_pages, cookies=None, db_scan_id=None, job_id=None, callback=None):
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
            return [{"url": self.url, "issue": "demo"}]

    # Route A import path
    import scanner.engine as engine
    monkeypatch.setattr(engine, "WebScanner", FakeWebScanner)
