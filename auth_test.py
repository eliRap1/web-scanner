import requests
import json
import time

BASE_URL = "http://localhost:8000"

REGISTER_URL = f"{BASE_URL}/register"
LOGIN_URL    = f"{BASE_URL}/login"
VERIFY_URL   = f"{BASE_URL}/verify"
LOGOUT_URL   = f"{BASE_URL}/logout"
SCAN_URL     = f"{BASE_URL}/scan"


def print_section(title):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def test_registration():
    print_section("TEST 1: USER REGISTRATION")

    payload = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "Test@1234",
        "confirm_password": "Test@1234"
    }

    r = requests.post(REGISTER_URL, json=payload)
    print(r.status_code, r.json())

    return r.status_code in (201, 400)


def test_login():
    print_section("TEST 2: USER LOGIN")

    payload = {
        "username": "testuser",
        "password": "Test@1234"
    }

    r = requests.post(LOGIN_URL, json=payload)
    print(r.status_code, r.json())

    if r.status_code == 200:
        return r.json()["token"]

    return None


def test_verify(token):
    print_section("TEST 3: TOKEN VERIFY")

    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(VERIFY_URL, headers=headers)

    print(r.status_code, r.json())
    return r.status_code == 200


def test_invalid_login():
    print_section("TEST 4: INVALID LOGIN")

    r = requests.post(LOGIN_URL, json={
        "username": "testuser",
        "password": "Wrong@123"
    })

    print(r.status_code)
    return r.status_code == 401


def test_password_rules():
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
            "username": f"user{i}",
            "email": f"user{i}@x.com",
            "password": pw,
            "confirm_password": pw
        })

        if r.status_code == 422:
            passed += 1

    return passed == len(bad_passwords)


def test_scanner(token):
    print_section("TEST 6: SCANNER")

    headers = {"Authorization": f"Bearer {token}"}
    params = {
        "url": "https://www.hackthissite.org/",
        "max_pages": 15
    }

    r = requests.post(SCAN_URL, headers=headers, params=params)

    print(r.status_code)
    try:
        data = r.json()
        print(json.dumps(data, indent=2))
    except Exception:
        print(r.text)
        return False

    return r.status_code == 200 and isinstance(data, list)


def test_logout(token):
    print_section("TEST 7: LOGOUT")

    headers = {"Authorization": f"Bearer {token}"}
    r = requests.post(LOGOUT_URL, headers=headers, json={})

    print(r.status_code, r.json())

    # token must now be invalid
    r2 = requests.get(VERIFY_URL, headers=headers)
    return r2.status_code == 401


def main():
    print("Starting full auth + scanner tests...")
    time.sleep(1)

    results = []

    results.append(("Registration", test_registration()))
    token = test_login()
    results.append(("Login", token is not None))

    if token:
        results.append(("Verify", test_verify(token)))
        results.append(("Invalid Login", test_invalid_login()))
        results.append(("Password Rules", test_password_rules()))
        results.append(("Scanner", test_scanner(token)))
        results.append(("Logout", test_logout(token)))

    print_section("SUMMARY")
    for name, ok in results:
        print(f"{'✓' if ok else '✗'} {name}")

    print(f"\nPassed {sum(ok for _, ok in results)}/{len(results)} tests")


if __name__ == "__main__":
    main()
