import requests
from requests import Session 
from collections import deque
from urllib.parse import urlparse

from scanner.models import ScanTarget
from scanner.extractor import extract_links, extract_forms
from scanner.scope import is_in_scope, normalize_url
import time

TIME_LIMIT_BETWEEN_REQUESTS = 0  # Time delay between requests in seconds

class WebScanner:
    def __init__(self, url: str, max_pages: int = 100, session: Session = None):
        self.start_url = normalize_url(url)
        self.max_pages = max_pages
        self.visited = set()
        self.queue = deque([self.start_url])
        self.targets: list[ScanTarget] = []
        
        # Use the provided session or create a fresh one
        self.session = session if session else requests.Session()
        
        # Set to store unique signatures to prevent duplicates
        self.seen_targets = set()

    def scan(self) -> list[ScanTarget]:
        while self.queue and len(self.visited) < self.max_pages:
            url = self.queue.popleft()
            url = normalize_url(url)

            if url in self.visited:
                continue

            try:
                # Use self.session instead of requests.get
                response = self.session.get(url, timeout=5) 
                time.sleep(TIME_LIMIT_BETWEEN_REQUESTS)  # Rate limiting
                
                if "text/html" not in response.headers.get("Content-Type", ""):
                    continue
            except Exception as e:
                print(f"Error scanning {url}: {e}")
                continue

            self.visited.add(url)
            html = response.text

            parsed = urlparse(url)
            
            # --- Handle URL Parameters (GET) ---
            if parsed.query:
                params = [p.split("=")[0] for p in parsed.query.split("&") if p]
                
                # Create a unique ID for this GET request: "GET|URL|params"
                # We sort params just in case order matters in browser but not for the attack surface
                sig = f"GET|{url}|{','.join(sorted(params))}"
                
                if sig not in self.seen_targets:
                    self.targets.append(ScanTarget(
                        url=url,
                        method="GET",
                        parameters=params,
                        context="url"
                    ))
                    self.seen_targets.add(sig)

            # --- Handle Forms ---
            for form in extract_forms(html, url):
                param_names = [f.name for f in form.fields]
                
                # Create a unique ID for this Form: "POST|ActionURL|params"
                # We use sorted(params) because "user,pass" is the same form as "pass,user"
                sig = f"{form.method.upper()}|{form.action}|{','.join(sorted(param_names))}"
                
                if sig not in self.seen_targets:
                    self.targets.append(ScanTarget(
                        url=form.action,
                        method=form.method.upper(),
                        parameters=param_names,
                        context="form"
                    ))
                    self.seen_targets.add(sig)

            # --- Handle Links for Crawling ---
            for link in extract_links(html, url):
                if is_in_scope(self.start_url, link):
                    self.queue.append(link)

        return self.targets