import requests
from requests import Session
from scanner.extractor import extract_forms

class AuthenticationManager:
    def __init__(self):
        self.session = requests.Session()

    def login(self, login_url: str, username: str, password: str) -> Session:
        """
        Attempts to log in to given URL.
        Returns a Session object if successful.
        """
        print(f"[*] Attempting to login at: {login_url}")

        # 0. STEP 0: Capture Cookies BEFORE login
        # We use .copy() so we don't reference the live object
        cookies_before = self.session.cookies.get_dict()

        try:
            response = self.session.get(login_url, timeout=10)
        except Exception as e:
            print(f"[-] Failed to reach login page: {e}")
            return None

        forms = extract_forms(response.text, login_url)
        if not forms:
            print("[-] No login form found on this page.")
            return None

        # ... (Same logic as before to find form) ...
        login_form = None
        for form in forms:
            for field in form.fields:
                if field.type == "password":
                    login_form = form
                    break
            if login_form:
                break
        
        if login_form is None:
            print("[-] No password field found in any form on this page.")
            return None

        payload = {}
        user_field_found = False

        for field in login_form.fields:
            name_lower = field.name.lower()
            
            if field.type == "password":
                payload[field.name] = password
            elif "user" in name_lower or "email" in name_lower:
                payload[field.name] = username
                user_field_found = True
            else:
                payload[field.name] = field.value

        if not user_field_found:
             for field in login_form.fields:
                if field.type == "text":
                    payload[field.name] = username
                    break

        # 1. STEP 1: Submit Login
        print(f"[*] Submitting login to: {login_form.action}")
        post_resp = self.session.post(
            login_form.action, 
            data=payload, 
            timeout=10
        )

        # 2. STEP 2: Capture Cookies AFTER login
        cookies_after = self.session.cookies.get_dict()

        # 3. STEP 3: The Reliable Check
        # If cookies changed (new keys or values changed), we are likely logged in
        if cookies_after != cookies_before:
            print("[+] Login Successful! (New Cookies detected)")
            return self.session

        # 4. STEP 4: Fallback Checks (If cookies didn't change, but URL moved)
        if post_resp.url != login_url:
            # Some sites set cookies on the redirect page, check final URL
            print("[+] Login Successful! (Redirect detected)")
            return self.session
            
        # 5. FINAL STEP: Failure
        print("[-] Login Failed (No Cookies, No Redirect)")
        return None