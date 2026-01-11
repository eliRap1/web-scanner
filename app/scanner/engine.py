from collections import deque
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright
from scanner.models import ScanTarget
from scanner.extractor import extract_links, extract_forms
from scanner.scope import is_in_scope, normalize_url
import copy

from db.database import get_connection, insert_log

class WebScanner:
    def __init__(self, url: str, max_pages: int = 100, cookies=None, job_id: str = None, db_scan_id: int = None, callback=None):
        self.start_url = normalize_url(url)
        self.max_pages = max_pages
        self.visited = set()
        self.queue = deque([self.start_url])
        self.targets: list[ScanTarget] = []
        self.seen_targets = set()
        self.cookies = cookies
        self.job_id = job_id
        self.db_scan_id = db_scan_id
        self.callback = callback

    def scan(self) -> list[ScanTarget]:
        # 1. Open Database Connection
        conn = get_connection()
        
        try:
            # 2. Log Scan Start
            insert_log(conn, self.db_scan_id, "info", f"Scan started for {self.start_url}")

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                
                target_domain = urlparse(self.start_url).netloc
                
                if self.cookies:
                    print(f"[*] Injecting cookies for domain: {target_domain}")
                    for name, value in self.cookies.items():
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
                        # 3. Log / Callback: Update Progress (URL)
                        if self.db_scan_id:
                            insert_log(conn, self.db_scan_id, "info", f"Visiting: {url}")
                        if self.callback:
                            self.callback(self.job_id, {
                                "current_url": url,
                                "visited_count": len(self.visited),
                                "found_count": len(self.targets),
                                "status": "running"
                            })

                        response = page.goto(url, timeout=10000, wait_until="networkidle")
                    except Exception as e:
                        # 4. Log Error Loading Page (✅ FIXED: Use 'e' not 'scan_error')
                        if self.db_scan_id:
                            insert_log(conn, self.db_scan_id, "error", f"Failed to load {url}: {str(e)}")
                        print(f"[-] Error loading {url}: {e}")
                        continue
                    
                    # --- Heuristic Logic (Pagination) ---
                    if "?page=" in url:
                        try:
                            parts = url.split("?page=")
                            if len(parts) == 2:
                                base_part, page_part = parts
                                if page_part.isdigit():
                                    current_page = int(page_part)
                                    for next_page_num in range(current_page + 1, current_page + 4):
                                        next_url = f"{base_part}?page={next_page_num}"
                                        
                                        if is_in_scope(self.start_url, next_url) and next_url not in self.visited:
                                            print(f"[*] Heuristic: Auto-discovered next page {next_page_num}")
                                            self.queue.append(next_url)
                        except Exception as heur_e:
                            pass

                    # --- Main Extraction Logic ---
                    parsed = urlparse(url)
                    
                    # 1. URL Parameters
                    if parsed.query:
                        params = [p.split("=")[0] for p in parsed.query.split("&") if p]
                        sig = f"GET|{url}|{','.join(sorted(params))}"
                        if sig not in self.seen_targets:
                            new_target = ScanTarget(url=url, method="GET", parameters=params, context="url")
                            self.targets.append(new_target)
                            self.seen_targets.add(sig)
                            
                            # CALLBACK: Send new target immediately
                            if self.callback:
                                self.callback(self.job_id, {"new_target": new_target})

                    # 2. Forms
                    for form in extract_forms(page, url):
                        param_names = [f.name for f in form.fields]
                        if not param_names: continue 

                        sig = f"{form.method.upper()}|{form.action}|{','.join(sorted(param_names))}"
                        if sig not in self.seen_targets:
                            new_target = ScanTarget(
                                url=form.action,
                                method=form.method.upper(),
                                parameters=param_names,
                                context="form"
                            )
                            self.targets.append(new_target)
                            self.seen_targets.add(sig)
                            
                            # CALLBACK: Send new target immediately
                            if self.callback:
                                self.callback(self.job_id, {"new_target": new_target})

                    # 3. Links
                    for link in extract_links(page, url):
                        if is_in_scope(self.start_url, link):
                            self.queue.append(link)
                    
                    self.visited.add(url)

            # 5. Log Scan Completed (Success)
            insert_log(conn, self.db_scan_id, "info", f"Scan completed. Visited: {len(self.visited)}, Found: {len(self.targets)}")
            return self.targets

        except Exception as scan_error:  # ✅ NOW scan_error is defined!
            # 6. Log Fatal Scan Error
            insert_log(conn, self.db_scan_id, "error", f"Fatal scan error: {str(scan_error)}")
            raise scan_error
            
        finally:
            # 7. Close Database Connection
            conn.close()