"""
scanner/engine.py

Core Web Scanner - Crawls website and runs vulnerability tests.
Improved version with:
- URL parameter extraction from links
- Proper session management for vulnerability testing
- Progress callbacks during vuln testing
- Better error handling
"""

from collections import deque
from urllib.parse import urlparse, parse_qs, urlencode
import requests
from playwright.sync_api import sync_playwright

from scanner.models import ScanTarget
from scanner.extractor import extract_links, extract_forms
from scanner.scope import is_in_scope, normalize_url
from scanner.vulnerability_tester import VulnerabilityTester
from db.database import get_connection, insert_log


class WebScanner:
    def __init__(
        self, 
        url: str, 
        max_pages: int = 100, 
        cookies=None, 
        job_id: str = None, 
        db_scan_id: int = None, 
        callback=None
    ):
        self.start_url = normalize_url(url)
        self.max_pages = max_pages
        self.visited = set()
        self.queue = deque([self.start_url])
        self.targets: list[ScanTarget] = []
        self.seen_targets = set()
        self.cookies = cookies or {}
        self.job_id = job_id
        self.db_scan_id = db_scan_id
        self.callback = callback
        
        # Create requests session for vulnerability testing
        self.http_session = requests.Session()
        self.http_session.headers.update({
            'User-Agent': 'WebScanner/1.0 (Security Testing)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })

    def _extract_url_params(self, url: str) -> ScanTarget | None:
        """Extract parameters from URL query string and create a ScanTarget."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return None
            
        param_names = list(params.keys())
        
        # Create signature to avoid duplicates
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        sig = f"GET|{base_url}|{','.join(sorted(param_names))}"
        
        if sig in self.seen_targets:
            return None
            
        self.seen_targets.add(sig)
        
        return ScanTarget(
            url=base_url,
            method="GET",
            parameters=param_names,
            context="url"
        )

    def _update_progress(self, phase: str, **kwargs):
        """Send progress update via callback."""
        if self.callback:
            data = {
                "phase": phase,
                "visited_count": len(self.visited),
                "found_count": len(self.targets),
                "status": "running",
                **kwargs
            }
            self.callback(self.job_id, data)

    def scan(self) -> dict:
        """
        Main scan method.
        
        Returns:
            dict with 'targets' and 'findings' lists
        """
        conn = get_connection()
        findings = []
        
        try:
            insert_log(conn, self.db_scan_id, "info", f"Scan started for {self.start_url}")

            # ============================================
            # PHASE 1: CRAWLING
            # ============================================
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                
                target_domain = urlparse(self.start_url).netloc
                
                # Inject cookies into Playwright
                if self.cookies:
                    insert_log(conn, self.db_scan_id, "info", f"Injecting {len(self.cookies)} cookies")
                    for name, value in self.cookies.items():
                        context.add_cookies([{
                            "name": name, 
                            "value": value, 
                            "domain": target_domain,
                            "path": "/"
                        }])
                        # Also add to requests session
                        self.http_session.cookies.set(name, value, domain=target_domain)
                
                page = context.new_page()

                while self.queue and len(self.visited) < self.max_pages:
                    url = self.queue.popleft()
                    url = normalize_url(url)

                    if url in self.visited:
                        continue

                    try:
                        # Progress update
                        self._update_progress(
                            phase="crawling",
                            current_url=url
                        )
                        
                        if self.db_scan_id:
                            insert_log(conn, self.db_scan_id, "info", f"Visiting: {url}")

                        response = page.goto(url, timeout=15000, wait_until="networkidle")
                        
                        if not response:
                            continue

                    except Exception as e:
                        insert_log(conn, self.db_scan_id, "warning", f"Failed to load {url}: {str(e)[:100]}")
                        self.visited.add(url)
                        continue

                    # -------------------------
                    # 1. Extract URL Parameters
                    # -------------------------
                    url_target = self._extract_url_params(url)
                    if url_target:
                        self.targets.append(url_target)
                        if self.callback:
                            self.callback(self.job_id, {"new_target": url_target})

                    # -------------------------
                    # 2. Extract Forms
                    # -------------------------
                    for form in extract_forms(page, url):
                        param_names = [f.name for f in form.fields]
                        if not param_names:
                            continue 

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
                            
                            if self.callback:
                                self.callback(self.job_id, {"new_target": new_target})

                    # -------------------------
                    # 3. Extract Links for Queue
                    # -------------------------
                    for link in extract_links(page, url):
                        if is_in_scope(self.start_url, link) and link not in self.visited:
                            # Also check for URL params in discovered links
                            link_target = self._extract_url_params(link)
                            if link_target:
                                self.targets.append(link_target)
                                if self.callback:
                                    self.callback(self.job_id, {"new_target": link_target})
                            
                            self.queue.append(link)
                    
                    self.visited.add(url)

                # Close browser
                browser.close()

            insert_log(
                conn, self.db_scan_id, "info", 
                f"Crawling completed. Visited: {len(self.visited)}, Targets found: {len(self.targets)}"
            )

            # ============================================
            # PHASE 2: VULNERABILITY TESTING
            # ============================================
            if self.targets:
                self._update_progress(
                    phase="testing",
                    current_url="Starting vulnerability tests...",
                    total_targets=len(self.targets)
                )
                
                insert_log(conn, self.db_scan_id, "info", f"Starting vulnerability testing on {len(self.targets)} targets")

                tester = VulnerabilityTester(
                    session=self.http_session,
                    db_scan_id=self.db_scan_id,
                    callback=self.callback,
                    job_id=self.job_id
                )

                for idx, target in enumerate(self.targets):
                    self._update_progress(
                        phase="testing",
                        current_url=target.url,
                        testing_target=idx + 1,
                        total_targets=len(self.targets)
                    )
                    
                    try:
                        vulns = tester.test_target(target)
                        findings.extend(vulns)
                    except Exception as e:
                        insert_log(
                            conn, self.db_scan_id, "warning", 
                            f"Error testing {target.url}: {str(e)[:100]}"
                        )

                insert_log(
                    conn, self.db_scan_id, "info", 
                    f"Vulnerability testing completed. Found {len(findings)} potential vulnerabilities"
                )

            # ============================================
            # PHASE 3: COMPLETE
            # ============================================
            insert_log(
                conn, self.db_scan_id, "info", 
                f"Scan completed. Visited: {len(self.visited)}, Targets: {len(self.targets)}, Findings: {len(findings)}"
            )
            
            return {
                "targets": [self._target_to_dict(t) for t in self.targets],
                "findings": findings,
                "stats": {
                    "pages_visited": len(self.visited),
                    "targets_found": len(self.targets),
                    "vulnerabilities_found": len(findings)
                }
            }

        except Exception as scan_error:
            insert_log(conn, self.db_scan_id, "error", f"Fatal scan error: {str(scan_error)}")
            raise scan_error
            
        finally:
            conn.close()

    def _target_to_dict(self, target: ScanTarget) -> dict:
        """Convert ScanTarget dataclass to dict for JSON serialization."""
        return {
            "url": target.url,
            "method": target.method,
            "parameters": target.parameters,
            "context": target.context
        }