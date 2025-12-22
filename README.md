# Web Scanner (Auth + Token)

This repository currently contains the **Authentication** part of the Web-Scanner project:

- Registration API (`register.py`) – creates users with password hashing and validation
- Login API (`login.py`) – authenticates users, issues session tokens, verifies, logout, and token refresh
- SQLite DB layer (`database.py`) – schema + migrations + password hashing + session management

## Quick start

### 1) Install requirements

```bash
pip install fastapi uvicorn pydantic passlib[bcrypt] pytest httpx
```

> If you don’t install `passlib[bcrypt]`, `database.py` can fall back to SHA-256,
> but the recommended setup is bcrypt.

### 2) Initialize the database (optional)

```bash
python database.py
```

This creates `web_scanner.db` in the current working directory.

### 3) Run the services

Terminal 1:
```bash
python register.py
```

Terminal 2:
```bash
python login.py
```

- Registration: `http://localhost:8001`
- Login/Token: `http://localhost:8002`

### 4) API documentation

See: `docs/API.md`

### 5) Run tests

```bash
pytest -q
```

## Environment variables

- `WEB_SCANNER_DB` – override the SQLite DB path (used mainly for tests)

Example:

```bash
export WEB_SCANNER_DB=/tmp/web_scanner_dev.db
python login.py
```
