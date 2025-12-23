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
