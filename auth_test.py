"""
Complete Authentication Flow Test
Tests registration, login, token validation, and logout
"""

import requests
import json

# Configuration
REGISTER_URL = "http://localhost:8001/register"
LOGIN_URL = "http://localhost:8002/login"
VERIFY_URL = "http://localhost:8002/verify"
LOGOUT_URL = "http://localhost:8002/logout"

def print_section(title):
    print("\n" + "="*60)
    print(title)
    print("="*60)

def test_registration():
    """Test user registration"""
    print_section("TEST 1: USER REGISTRATION")
    
    payload = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "Test@1234",
        "confirm_password": "Test@1234"
    }
    print(len(payload["password"].encode("utf-8")))
    print(f"POST {REGISTER_URL}")
    print(f"Payload: {json.dumps(payload, indent=2)}")
    
    try:
        response = requests.post(REGISTER_URL, json=payload)
        print(f"\nStatus: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 201:
            print("✓ Registration successful!")
            return True
        elif response.status_code == 400 and "already taken" in response.json().get("detail", ""):
            print("⚠️  User already exists (this is OK for testing)")
            return True
        else:
            print("✗ Registration failed!")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_login():
    """Test user login"""
    print_section("TEST 2: USER LOGIN")
    
    payload = {
        "username": "testuser",
        "password": "Test@1234"
    }
    
    print(f"POST {LOGIN_URL}")
    print(f"Payload: {json.dumps(payload, indent=2)}")
    
    try:
        response = requests.post(LOGIN_URL, json=payload)
        print(f"\nStatus: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            data = response.json()
            token = data.get("token")
            print(f"\n✓ Login successful!")
            print(f"Token: {token[:20]}...")
            return token
        else:
            print("✗ Login failed!")
            return None
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return None

def test_token_validation(token):
    """Test token validation"""
    print_section("TEST 3: TOKEN VALIDATION")
    
    print(f"GET {VERIFY_URL}?token={token[:20]}...")
    
    try:
        response = requests.get(VERIFY_URL, params={"token": token})
        print(f"\nStatus: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            print("✓ Token is valid!")
            return True
        else:
            print("✗ Token validation failed!")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_invalid_login():
    """Test login with wrong password"""
    print_section("TEST 4: INVALID LOGIN (Wrong Password)")
    
    payload = {
        "username": "testuser",
        "password": "WrongPassword123!"
    }
    
    print(f"POST {LOGIN_URL}")
    print(f"Payload: {json.dumps(payload, indent=2)}")
    
    try:
        response = requests.post(LOGIN_URL, json=payload)
        print(f"\nStatus: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 401:
            print("✓ Correctly rejected invalid credentials!")
            return True
        else:
            print("✗ Should have rejected invalid credentials!")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_password_requirements():
    """Test password validation"""
    print_section("TEST 5: PASSWORD REQUIREMENTS")
    
    test_cases = [
        ("short", "Short@1", "Too short (< 8 chars)"),
        ("no_upper", "password@123", "No uppercase letter"),
        ("no_lower", "PASSWORD@123", "No lowercase letter"),
        ("no_digit", "Password@", "No digit"),
        ("no_special", "Password123", "No special character"),
    ]
    
    passed = 0
    for name, password, description in test_cases:
        payload = {
            "username": f"test_{name}",
            "email": f"{name}@example.com",
            "password": password,
            "confirm_password": password
        }
        
        print(f"\nTesting: {description}")
        print(f"Password: {password}")
        
        try:
            response = requests.post(REGISTER_URL, json=payload)
            if response.status_code == 422:  # Validation error
                print(f"  ✓ Correctly rejected")
                passed += 1
            else:
                print(f"  ✗ Should have been rejected")
        except Exception as e:
            print(f"  ✗ Error: {e}")
    
    print(f"\nPassed {passed}/{len(test_cases)} validation tests")
    return passed == len(test_cases)

def test_logout(token):
    """Test logout"""
    print_section("TEST 6: LOGOUT")
    
    print(f"POST {LOGOUT_URL}")
    print(f"Token: {token[:20]}...")
    
    try:
        response = requests.post(LOGOUT_URL, params={"token": token})
        print(f"\nStatus: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            print("✓ Logout successful!")
            
            # Try to use the token again (should fail)
            print("\nVerifying token is now invalid...")
            verify_response = requests.get(VERIFY_URL, params={"token": token})
            
            if verify_response.status_code == 401:
                print("✓ Token correctly invalidated!")
                return True
            else:
                print("✗ Token should be invalid after logout!")
                return False
        else:
            print("✗ Logout failed!")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def main():
    print("\n" + "="*60)
    print("AUTHENTICATION FLOW TEST")
    print("="*60)
    print("\nMake sure the servers are running:")
    print("  1. python register.py  (port 8001)")
    print("  2. python login.py     (port 8002)")
    print("\nStarting tests in 3 seconds...")
    
    import time
    time.sleep(3)
    
    results = []
    
    # Test 1: Registration
    results.append(("Registration", test_registration()))
    
    # Test 2: Login
    token = test_login()
    results.append(("Login", token is not None))
    
    if token:
        # Test 3: Token validation
        results.append(("Token Validation", test_token_validation(token)))
        
        # Test 4: Invalid login
        results.append(("Invalid Login", test_invalid_login()))
        
        # Test 5: Password requirements
        results.append(("Password Requirements", test_password_requirements()))
        
        # Test 6: Logout
        results.append(("Logout", test_logout(token)))
    else:
        print("\n⚠️  Skipping remaining tests (login failed)")
    
    # Summary
    print_section("TEST SUMMARY")
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed!")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
    
    return passed == total

if __name__ == "__main__":
    try:
        success = main()
        exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user")
        exit(1)
    except Exception as e:
        print(f"\n\n✗ Test suite failed: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
