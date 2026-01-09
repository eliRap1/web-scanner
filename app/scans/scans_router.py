from fastapi import APIRouter, Request, HTTPException
from scanner.engine import WebScanner
from scanner.models import ScanTarget
from scanner.auth_manager import AuthenticationManager
from typing import List, Optional
# We no longer need 'requests' import here because Playwright handles it
import requests 

router = APIRouter(tags=["scanner"])

@router.post("/", response_model=List[ScanTarget])
def start_scan(
    request: Request,
    url: str,
    max_pages: int = 30,
    target_login_url: Optional[str] = None, 
    target_username: Optional[str] = None,
    target_password: Optional[str] = None
):
    cookies_to_pass = None

    # 1. Try Login (If credentials provided)
    if target_username and target_password and target_login_url:
        auth_manager = AuthenticationManager()
        print(f"[*] Attempting login...") # We keep using requests for the LOGIN step
        
        # Temp session for login
        login_session = requests.Session() 
        logged_in_session = auth_manager.login(target_login_url, target_username, target_password)
        
        if logged_in_session:
            print("[+] Login Success.")
            # EXTRACT COOKIES to pass to Playwright
            cookies_to_pass = requests.utils.dict_from_cookiejar(logged_in_session.cookies)
        else:
            print("[-] Login Failed. Scanning as Guest.")

    # 2. Start Scanner (Playwright)
    # We pass the cookies if we got them
    scanner = WebScanner(
        url=url,
        max_pages=max_pages,
        cookies=cookies_to_pass
    )

    return scanner.scan()