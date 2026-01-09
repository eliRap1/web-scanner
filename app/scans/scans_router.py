from fastapi import APIRouter, Request, HTTPException
from scanner.engine import WebScanner
from scanner.models import ScanTarget
from scanner.auth_manager import AuthenticationManager
from typing import List, Optional
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
    # 1. Initialize Default Session (Guest)
    session = requests.Session()

    # 2. Try Authentication Logic
    if target_username and target_password and target_login_url:
        auth_manager = AuthenticationManager()
        print(f"[*] Trying to login to {target_login_url}...")
        
        logged_in_session = auth_manager.login(target_login_url, target_username, target_password)
        
        if logged_in_session:
            print("[+] Login Success! Scanning as user.")
            session = logged_in_session
        else:
            # 3. CHANGE: Instead of raising an error, fallback to Guest Mode
            print("[-] Login Failed. Starting scan as Guest (Unauthenticated)...")
            # We continue with the default 'guest' session created above
    else:
        print("[*] No credentials provided. Starting scan as Guest (Unauthenticated)...")

    # 4. Run Scan with whichever session we have (User or Guest)
    scanner = WebScanner(
        url=url,
        max_pages=max_pages,
        session=session
    )

    return scanner.scan()