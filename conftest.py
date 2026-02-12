"""
Pytest configuration and fixtures for web-scanner tests.
"""
import pytest
import requests

BASE_URL = "http://localhost:8000"


@pytest.fixture(scope="session")
def test_user():
    """Test user credentials."""
    return {
        "username": "testuser",
        "email": "test@example.com",
        "password": "Test@1234"
    }


@pytest.fixture(scope="session")
def token(test_user):
    """
    Fixture that provides an authentication token for tests.

    Registers the test user if needed, then logs in to get a token.
    This fixture has session scope so the token is reused across tests.
    """
    # Try to register (may fail if user exists, that's OK)
    try:
        requests.post(
            f"{BASE_URL}/register",
            json={
                "username": test_user["username"],
                "email": test_user["email"],
                "password": test_user["password"],
                "confirm_password": test_user["password"]
            },
            timeout=10
        )
    except requests.RequestException:
        pass

    # Login to get token
    try:
        response = requests.post(
            f"{BASE_URL}/login",
            json={
                "username": test_user["username"],
                "password": test_user["password"]
            },
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            return data.get("token")
    except requests.RequestException:
        pass

    # If login failed, skip tests that need token
    pytest.skip("Could not obtain authentication token - is the server running?")


@pytest.fixture(scope="session")
def api_headers(token):
    """Provides authorization headers for API requests."""
    return {"Authorization": f"Bearer {token}"}
