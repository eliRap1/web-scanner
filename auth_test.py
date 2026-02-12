"""
Authentication and scanner tests for web-scanner API.

These tests can be run with pytest or as a standalone script.
When running with pytest, fixtures from conftest.py are used automatically.
"""
import requests
import json
import time
import pytest

BASE_URL = "http://localhost:8000"

REGISTER_URL = f"{BASE_URL}/register"
LOGIN_URL = f"{BASE_URL}/login"
VERIFY_URL = f"{BASE_URL}/verify"
LOGOUT_URL = f"{BASE_URL}/logout"
SCAN_URL = f"{BASE_URL}/scan"


def print_section(title):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def test_registration():
    """Test user registration endpoint."""
    print_section("TEST 1: USER REGISTRATION")

    payload = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "Test@1234",
        "confirm_password": "Test@1234"
    }

    r = requests.post(REGISTER_URL, json=payload, timeout=10)
    print(r.status_code, r.json())

    # 201 = new user created, 400 = user already exists
    assert r.status_code in (201, 400), f"Unexpected status: {r.status_code}"


def test_login():
    """Test user login endpoint."""
    print_section("TEST 2: USER LOGIN")

    payload = {
        "username": "testuser",
        "password": "Test@1234"
    }

    r = requests.post(LOGIN_URL, json=payload, timeout=10)
    print(r.status_code, r.json())

    assert r.status_code == 200, f"Login failed with status {r.status_code}"
    assert "token" in r.json(), "No token in response"


def test_verify(token):
    """Test token verification endpoint."""
    print_section("TEST 3: TOKEN VERIFY")

    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(VERIFY_URL, headers=headers, timeout=10)

    print(r.status_code, r.json())
    assert r.status_code == 200, f"Verify failed with status {r.status_code}"


def test_invalid_login():
    """Test that invalid credentials are rejected."""
    print_section("TEST 4: INVALID LOGIN")

    r = requests.post(LOGIN_URL, json={
        "username": "testuser",
        "password": "Wrong@123"
    }, timeout=10)

    print(r.status_code)
    assert r.status_code == 401, f"Expected 401, got {r.status_code}"


def test_password_rules():
    """Test that weak passwords are rejected."""
    print_section("TEST 5: PASSWORD RULES")

    bad_passwords = [
        "short",
        "password123",
        "PASSWORD@123",
        "Password@",
        "Password123"
    ]

    passed = 0
    for i, pw in enumerate(bad_passwords):
        r = requests.post(REGISTER_URL, json={
            "username": f"weakpwuser{i}",
            "email": f"weakpwuser{i}@x.com",
            "password": pw,
            "confirm_password": pw
        }, timeout=10)

        if r.status_code == 422:
            passed += 1
        print(f"  Password '{pw}': {r.status_code}")

    assert passed == len(bad_passwords), f"Only {passed}/{len(bad_passwords)} weak passwords rejected"


@pytest.mark.skip(reason="Scanner test requires external target - run manually")
def test_scanner(token):
    """Test scanner endpoint (requires external target)."""
    print_section("TEST 6: SCANNER")

    headers = {"Authorization": f"Bearer {token}"}
    params = {
        "url": "https://www.hackthissite.org/",
        "max_pages": 15
    }

    r = requests.post(SCAN_URL, headers=headers, params=params, timeout=60)

    print(r.status_code)
    try:
        data = r.json()
        print(json.dumps(data, indent=2))
    except Exception:
        print(r.text)
        pytest.fail("Failed to parse response as JSON")

    assert r.status_code == 200, f"Scanner failed with status {r.status_code}"


def test_logout(token):
    """Test logout endpoint invalidates token."""
    print_section("TEST 7: LOGOUT")

    headers = {"Authorization": f"Bearer {token}"}
    r = requests.post(LOGOUT_URL, headers=headers, json={}, timeout=10)

    print(r.status_code, r.json())

    # Note: After logout, the token from the fixture may still be cached
    # In a real test, we'd get a new token after logout
    assert r.status_code == 200, f"Logout failed with status {r.status_code}"


# ==================== STANDALONE RUNNER ====================

def main():
    """Run tests as a standalone script (not pytest)."""
    print("Starting full auth + scanner tests...")
    time.sleep(1)

    results = []

    # Registration
    try:
        test_registration()
        results.append(("Registration", True))
    except AssertionError as e:
        print(f"FAILED: {e}")
        results.append(("Registration", False))

    # Login
    token = None
    try:
        r = requests.post(LOGIN_URL, json={
            "username": "testuser",
            "password": "Test@1234"
        }, timeout=10)
        if r.status_code == 200:
            token = r.json().get("token")
        results.append(("Login", token is not None))
    except Exception as e:
        print(f"Login error: {e}")
        results.append(("Login", False))

    if token:
        # Verify
        try:
            test_verify(token)
            results.append(("Verify", True))
        except AssertionError:
            results.append(("Verify", False))

        # Invalid login
        try:
            test_invalid_login()
            results.append(("Invalid Login", True))
        except AssertionError:
            results.append(("Invalid Login", False))

        # Password rules
        try:
            test_password_rules()
            results.append(("Password Rules", True))
        except AssertionError:
            results.append(("Password Rules", False))

        # Scanner (commented out - needs external target)
        # try:
        #     test_scanner(token)
        #     results.append(("Scanner", True))
        # except Exception:
        #     results.append(("Scanner", False))

        # Logout
        try:
            test_logout(token)
            results.append(("Logout", True))
        except AssertionError:
            results.append(("Logout", False))

    print_section("SUMMARY")
    for name, ok in results:
        print(f"{'OK' if ok else 'FAIL'} {name}")

    print(f"\nPassed {sum(ok for _, ok in results)}/{len(results)} tests")


if __name__ == "__main__":
    main()
