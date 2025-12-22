import re
from datetime import datetime, timedelta


def test_register_success(register_client):
    payload = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "Test@1234",
        "confirm_password": "Test@1234",
    }
    r = register_client.post("/register", json=payload)
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["status"] == "ok"
    assert isinstance(data["user_id"], int)


def test_register_duplicate_username_email(register_client):
    p = {
        "username": "dupuser",
        "email": "dup@example.com",
        "password": "Test@1234",
        "confirm_password": "Test@1234",
    }
    r1 = register_client.post("/register", json=p)
    assert r1.status_code == 201, r1.text

    # same username
    p2 = dict(p)
    p2["email"] = "dup2@example.com"
    r2 = register_client.post("/register", json=p2)
    assert r2.status_code == 400
    assert "username" in r2.json().get("detail", "")

    # same email
    p3 = dict(p)
    p3["username"] = "dupuser2"
    r3 = register_client.post("/register", json=p3)
    assert r3.status_code == 400
    assert "email" in r3.json().get("detail", "")


def test_password_policy_rejects_bad_passwords(register_client):
    cases = [
        ("Short@1", "at least 8"),
        ("password@123", "uppercase"),
        ("PASSWORD@123", "lowercase"),
        ("Password@", "digit"),
        ("Password123", "special"),
    ]

    for idx, (pw, expected_hint) in enumerate(cases):
        payload = {
            "username": f"u{idx}xx",
            "email": f"u{idx}@example.com",
            "password": pw,
            "confirm_password": pw,
        }
        r = register_client.post("/register", json=payload)
        assert r.status_code == 422, r.text
        # We don't rely on exact pydantic wording, only that it's about password
        assert "password" in r.text.lower()


def test_login_verify_logout_flow(register_client, login_client):
    # register
    reg = {
        "username": "flowuser",
        "email": "flow@example.com",
        "password": "Test@1234",
        "confirm_password": "Test@1234",
    }
    assert register_client.post("/register", json=reg).status_code == 201

    # login
    r = login_client.post("/login", json={"username": "flowuser", "password": "Test@1234"})
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    assert isinstance(token, str) and len(token) > 20

    # verify (header)
    v = login_client.get("/verify", headers={"Authorization": f"Bearer {token}"})
    assert v.status_code == 200, v.text
    assert v.json()["valid"] is True

    # logout
    lo = login_client.post("/logout", json={}, headers={"Authorization": f"Bearer {token}"})
    assert lo.status_code == 200, lo.text

    # token should be invalid now
    v2 = login_client.get("/verify", headers={"Authorization": f"Bearer {token}"})
    assert v2.status_code == 401


def test_login_wrong_password(register_client, login_client):
    reg = {
        "username": "badpwuser",
        "email": "badpw@example.com",
        "password": "Test@1234",
        "confirm_password": "Test@1234",
    }
    assert register_client.post("/register", json=reg).status_code == 201

    r = login_client.post("/login", json={"username": "badpwuser", "password": "Wrong@1234"})
    assert r.status_code == 401


def test_expired_token_is_rejected_and_removed(db_module, login_client, register_client):
    # register user
    reg = {
        "username": "expireuser",
        "email": "expire@example.com",
        "password": "Test@1234",
        "confirm_password": "Test@1234",
    }
    assert register_client.post("/register", json=reg).status_code == 201

    # create a token that is already expired
    conn = db_module.get_connection()
    try:
        user = db_module.get_user_by_username(conn, "expireuser")
        token = db_module.create_session(conn, user["user_id"], expires_in_hours=-1)
    finally:
        conn.close()

    # verify should fail
    v = login_client.get("/verify", headers={"Authorization": f"Bearer {token}"})
    assert v.status_code == 401

    # session should have been deleted on validate
    conn = db_module.get_connection()
    try:
        row = conn.execute("SELECT 1 FROM Sessions WHERE token = ?", (token,)).fetchone()
        assert row is None
    finally:
        conn.close()


def test_refresh_rotates_token(register_client, login_client):
    reg = {
        "username": "refreshuser",
        "email": "refresh@example.com",
        "password": "Test@1234",
        "confirm_password": "Test@1234",
    }
    assert register_client.post("/register", json=reg).status_code == 201

    login = login_client.post("/login", json={"username": "refreshuser", "password": "Test@1234"})
    assert login.status_code == 200
    old_token = login.json()["token"]

    ref = login_client.post("/refresh", json={}, headers={"Authorization": f"Bearer {old_token}"})
    assert ref.status_code == 200, ref.text
    new_token = ref.json()["token"]
    assert new_token != old_token

    # new token works
    v_new = login_client.get("/verify", headers={"Authorization": f"Bearer {new_token}"})
    assert v_new.status_code == 200

    # old token is invalid
    v_old = login_client.get("/verify", headers={"Authorization": f"Bearer {old_token}"})
    assert v_old.status_code == 401
