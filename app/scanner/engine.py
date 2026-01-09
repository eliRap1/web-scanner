from collections import deque
from urllib.parse import urlparse  # Ensure urlparse is imported
from playwright.sync_api import sync_playwright
from scanner.models import ScanTarget
from scanner.extractor import extract_links, extract_forms
from scanner.scope import is_in_scope, normalize_url

class WebScanner:
    def __init__(self, url: str, max_pages: int = 100, cookies=None):
        self.start_url = normalize_url(url)
        self.max_pages = max_pages
        self.visited = set()
        self.queue = deque([self.start_url])
        self.targets: list[ScanTarget] = []
        self.seen_targets = set()
        
        # Auth Cookies (passed from AuthManager)
        self.cookies = cookies

    def scan(self) -> list[ScanTarget]:
        # Launch Browser
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            
            # FIX: Extract domain to tell Playwright where to apply cookies
            target_domain = urlparse(self.start_url).netloc
            
            if self.cookies:
                print(f"[*] Injecting cookies for domain: {target_domain}")
                for name, value in self.cookies.items():
                    # Playwright REQUIRES domain (or url) to work
                    context.add_cookies([{
                        "name": name, 
                        "value": value, 
                        "domain": target_domain,
                        "path": "/"
                    }])
            
            page = context.new_page()

            while self.queue and len(self.visited) < self.max_pages:
                url = self.queue.popleft()
                url = normalize_url(url)

                if url in self.visited:
                    continue

                try:
                    print(f"[*] Scanning (Browser): {url}")
                    response = page.goto(url, timeout=10000, wait_until="networkidle")
                except Exception as e:
                    print(f"[-] Error loading {url}: {e}")
                    continue

                self.visited.add(url)
                
                # Extracting now happens from the rendered page (page object)
                parsed = urlparse(url)
                
                # 1. URL Parameters
                if parsed.query:
                    params = [p.split("=")[0] for p in parsed.query.split("&") if p]
                    sig = f"GET|{url}|{','.join(sorted(params))}"
                    if sig not in self.seen_targets:
                        self.targets.append(ScanTarget(url=url, method="GET", parameters=params, context="url"))
                        self.seen_targets.add(sig)

                # 2. Forms
                for form in extract_forms(page, url):
                    param_names = [f.name for f in form.fields]
                    if not param_names: continue # Skip empty forms if needed

                    sig = f"{form.method.upper()}|{form.action}|{','.join(sorted(param_names))}"
                    if sig not in self.seen_targets:
                        self.targets.append(ScanTarget(
                            url=form.action,
                            method=form.method.upper(),
                            parameters=param_names,
                            context="form"
                        ))
                        self.seen_targets.add(sig)

                # 3. Links
                for link in extract_links(page, url):
                    if is_in_scope(self.start_url, link):
                        self.queue.append(link)

            # Cleanup
            browser.close()
            return self.targets