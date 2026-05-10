import logging
import requests
from requests import Session
from scanner.extractor import extract_forms

logger = logging.getLogger(__name__)


class AuthenticationManager:
    def __init__(self):
        self.session = requests.Session()

    def login(self, login_url: str, username: str, password: str) -> Session:
        """
        Attempts to log in to the given URL by discovering and submitting a
        login form that contains a password field.

        Returns the requests.Session with the captured cookies if login
        appears successful, or None on failure.
        """
        logger.info("[auth] Attempting login at: %s", login_url)

        cookies_before = self.session.cookies.get_dict()

        try:
            response = self.session.get(login_url, timeout=10)
        except Exception as e:
            logger.warning("[auth] Failed to reach login page: %s", e)
            return None

        forms = extract_forms(response.text, login_url)
        if not forms:
            logger.warning("[auth] No forms found on login page: %s", login_url)
            return None

        # Find a form that contains a password field.
        login_form = None
        for form in forms:
            for field in form.fields:
                if field.type == "password":
                    login_form = form
                    break
            if login_form:
                break

        if login_form is None:
            logger.warning("[auth] No login form with a password field found at: %s", login_url)
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

        logger.info("[auth] Submitting login form to: %s", login_form.action)
        post_resp = self.session.post(
            login_form.action,
            data=payload,
            timeout=10
        )

        cookies_after = self.session.cookies.get_dict()

        if cookies_after != cookies_before:
            logger.info("[auth] Login successful (new cookies detected)")
            return self.session

        if post_resp.url != login_url:
            logger.info("[auth] Login successful (redirect detected)")
            return self.session

        logger.warning("[auth] Login failed (no new cookies, no redirect)")
        return None
