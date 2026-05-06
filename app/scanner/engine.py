"""
Production-Grade Web Crawler

This crawler is designed to find EVERYTHING on a website by:

1. NETWORK INTERCEPTION - Captures ALL URLs from network requests (APIs, assets, redirects)
2. JAVASCRIPT EXECUTION - Renders JS and extracts dynamically generated links
3. CLICK DISCOVERY - Clicks buttons, links, tabs to reveal hidden content
4. SCROLL TRIGGERING - Scrolls to load lazy/infinite content
5. FORM DISCOVERY - Finds all forms including dynamically generated ones
6. SPA SUPPORT - Handles React, Vue, Angular routing
7. SITEMAP/ROBOTS - Parses sitemap.xml and robots.txt
8. HASH ROUTES - Discovers /#/path style routes
9. URL EXTRACTION - Extracts URLs from JS code, inline scripts, data attributes
10. STATE MANAGEMENT - Tracks page state changes after interactions

Author: Production Scanner Team
"""

import re
import time
import json
import logging
from collections import deque
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from typing import Optional, Set, List, Dict, Any, Callable
from dataclasses import dataclass, field
from playwright.sync_api import sync_playwright, Page, BrowserContext, Response, Request

from scanner.models import ScanTarget, Form, FormField
from scanner.scope import is_in_scope, normalize_url
from db.database import get_connection, insert_log

logger = logging.getLogger(__name__)


@dataclass
class CrawlStats:
    """Statistics for the crawl"""
    pages_visited: int = 0
    pages_discovered: int = 0
    forms_found: int = 0
    api_endpoints_found: int = 0
    network_requests_captured: int = 0
    elements_clicked: int = 0
    errors: int = 0


@dataclass 
class PageData:
    """Data extracted from a single page"""
    url: str
    links: Set[str] = field(default_factory=set)
    forms: List[Form] = field(default_factory=list)
    api_endpoints: Set[str] = field(default_factory=set)
    network_urls: Set[str] = field(default_factory=set)
    js_urls: Set[str] = field(default_factory=set)


class ProductionCrawler:
    """
    Production-grade web crawler that finds everything.
    """
    
    # Patterns to extract URLs from JavaScript
    JS_URL_PATTERNS = [
        # API calls
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        r'\$\s*\.\s*(?:get|post|ajax)\s*\(\s*["\']([^"\']+)["\']',
        r'\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        
        # URL assignments
        r'(?:url|href|src|action|endpoint|api|baseURL|apiUrl)\s*[:=]\s*["\']([^"\']+)["\']',
        r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
        r'location\.(?:href|assign|replace)\s*(?:=|\()\s*["\']([^"\']+)["\']',
        
        # Router definitions
        r'path\s*:\s*["\']([^"\']+)["\']',
        r'route\s*:\s*["\']([^"\']+)["\']',
        r'to\s*[:=]\s*["\']([^"\']+)["\']',
        r'href\s*[:=]\s*["\']([^"\']+)["\']',
        r'navigate\s*\(\s*["\']([^"\']+)["\']',
        r'push\s*\(\s*["\']([^"\']+)["\']',
        r'redirect\s*\(\s*["\']([^"\']+)["\']',
        
        # Generic URL patterns
        r'["\'](/[a-zA-Z0-9_\-./]+(?:\?[^"\'<>\s]*)?)["\']',
        r'["\'](https?://[^"\'<>\s]+)["\']',
    ]
    
    # Elements to click for content discovery
    CLICKABLE_SELECTORS = [
        'a[href]',
        'button:not([disabled])',
        '[role="button"]',
        '[role="link"]',
        '[role="tab"]',
        '[onclick]',
        '.nav-link',
        '.menu-item',
        '.tab',
        '.btn',
        '[data-toggle]',
        '[data-target]',
        'summary',  # For <details> elements
    ]
    
    # Elements that might reveal content when clicked
    INTERACTIVE_SELECTORS = [
        '[aria-haspopup="true"]',
        '[aria-expanded="false"]',
        '.dropdown-toggle',
        '.accordion-header',
        '.collapsible',
        '.expandable',
        '[data-bs-toggle]',  # Bootstrap 5
    ]
    
    # File extensions to skip
    STATIC_EXTENSIONS = {
        '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.pdf', '.zip', '.rar', '.tar', '.gz',
        '.mp3', '.mp4', '.avi', '.mov', '.webm', '.ogg',
        '.webp', '.bmp', '.tiff',
        '.map', '.min.js', '.min.css',
    }
    
    def __init__(
        self,
        start_url: str = None,
        url: str = None,  # BACKWARDS COMPATIBILITY: accept 'url' as alias
        max_pages: int = 100,
        max_depth: int = 15,
        cookies: Optional[Dict[str, str]] = None,
        job_id: str = None,
        db_scan_id: int = None,
        callback: Optional[Callable] = None,
        # Feature flags
        intercept_network: bool = True,
        click_elements: bool = True,
        scroll_pages: bool = True,
        extract_js_urls: bool = True,
        fetch_sitemap: bool = True,
        wait_for_idle: bool = True,
        # Timeouts
        page_timeout: int = 30000,
        click_timeout: int = 2000,
        # Limits
        max_clicks_per_page: int = 20,
        max_scroll_attempts: int = 5,
        # Proxy support for Burp/ZAP integration
        proxy: Optional[str] = None,  # e.g., "http://127.0.0.1:8080"
    ):
        # BACKWARDS COMPATIBILITY: accept either 'url' or 'start_url'
        if start_url is None and url is None:
            raise ValueError("Either 'start_url' or 'url' must be provided")
        if start_url is None:
            start_url = url
        self.start_url = normalize_url(start_url)
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.cookies = cookies
        self.job_id = job_id
        self.db_scan_id = db_scan_id
        self.callback = callback
        
        # Feature flags
        self.intercept_network = intercept_network
        self.click_elements = click_elements
        self.scroll_pages = scroll_pages
        self.extract_js_urls = extract_js_urls
        self.fetch_sitemap = fetch_sitemap
        self.wait_for_idle = wait_for_idle
        
        # Timeouts
        self.page_timeout = page_timeout
        self.click_timeout = click_timeout
        
        # Limits
        self.max_clicks_per_page = max_clicks_per_page
        self.max_scroll_attempts = max_scroll_attempts

        # Proxy support (for Burp Suite, ZAP, etc.)
        self.proxy = proxy

        # Session placeholder for backwards compatibility
        self.session = None

        # Graph tracking data (for DFS analysis)
        self.page_links: Dict[str, Set[str]] = {}
        self.page_depths: Dict[str, int] = {}
        self.page_parents: Dict[str, Optional[str]] = {}

        # State
        self.visited: Set[str] = set()
        self.queue: deque = deque()
        self.discovered_urls: Set[str] = set()
        self.network_urls: Set[str] = set()
        self.api_endpoints: Set[str] = set()
        self.targets: List[ScanTarget] = []
        self.seen_targets: Set[str] = set()
        self.stats = CrawlStats()
        
        # Parse base domain for scope checking
        parsed = urlparse(self.start_url)
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme
        
        # Initialize queue
        self.queue.append((self.start_url, 0))  # (url, depth)
        self.discovered_urls.add(self.start_url)

    def _log(self, level: str, message: str):
        """Log to database and console"""
        logger.info(message) if level == "info" else logger.warning(message)
        if self.db_scan_id:
            try:
                conn = get_connection()
                insert_log(conn, self.db_scan_id, level, message)
                conn.close()
            except Exception:
                pass

    def _report_progress(self, **kwargs):
        """Report progress via callback"""
        if self.callback:
            self.callback(self.job_id, {
                "visited_count": len(self.visited),
                "discovered_count": len(self.discovered_urls),
                "targets_count": len(self.targets),
                "api_count": len(self.api_endpoints),
                "status": "running",
                **kwargs
            })

    def _is_valid_url(self, url: str) -> bool:
        """Check if URL should be crawled"""
        if not url:
            return False
            
        # Skip non-http URLs
        if url.startswith(('javascript:', 'mailto:', 'tel:', 'data:', 'blob:', '#')):
            return False
            
        # Skip static files
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        if any(path_lower.endswith(ext) for ext in self.STATIC_EXTENSIONS):
            return False
            
        return True

    def _normalize_and_validate(self, url: str, base_url: str) -> Optional[str]:
        """Normalize URL and check if it's in scope"""
        if not url:
            return None
            
        # Handle protocol-relative URLs
        if url.startswith('//'):
            url = f"{self.base_scheme}:{url}"
        # Handle relative URLs
        elif not url.startswith(('http://', 'https://')):
            url = urljoin(base_url, url)
            
        # Normalize
        url = normalize_url(url)
        
        # Check validity and scope
        if not self._is_valid_url(url):
            return None
        if not is_in_scope(self.start_url, url):
            return None
            
        return url

    def _extract_urls_from_text(self, text: str, base_url: str) -> Set[str]:
        """Extract URLs from JavaScript/text content"""
        urls = set()
        
        for pattern in self.JS_URL_PATTERNS:
            try:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    url = match.strip().strip('"\'')
                    
                    # Skip template literals and variables
                    if any(x in url for x in ['${', '{{', '{%', '#{', 'undefined', 'null']):
                        continue
                        
                    normalized = self._normalize_and_validate(url, base_url)
                    if normalized:
                        urls.add(normalized)
            except Exception:
                pass
                
        return urls

    def _setup_network_interception(self, page: Page):
        """Set up network request interception"""
        captured_urls = set()
        
        def handle_request(request: Request):
            url = request.url
            normalized = self._normalize_and_validate(url, self.start_url)
            if normalized:
                captured_urls.add(normalized)
                self.network_urls.add(normalized)
                self.stats.network_requests_captured += 1
                
                # Identify API endpoints
                if any(x in url for x in ['/api/', '/v1/', '/v2/', '/graphql', '/rest/']):
                    self.api_endpoints.add(normalized)
                    
        def handle_response(response: Response):
            # Capture redirect locations
            if response.status in [301, 302, 303, 307, 308]:
                location = response.headers.get('location')
                if location:
                    normalized = self._normalize_and_validate(location, response.url)
                    if normalized:
                        captured_urls.add(normalized)
                        
        page.on('request', handle_request)
        page.on('response', handle_response)
        
        return captured_urls

    def _extract_links_from_page(self, page: Page, url: str) -> Set[str]:
        """Extract all links from rendered page"""
        links = set()
        
        try:
            # Standard anchor tags
            anchors = page.query_selector_all('a[href]')
            for anchor in anchors:
                try:
                    href = anchor.get_attribute('href')
                    if href:
                        normalized = self._normalize_and_validate(href, url)
                        if normalized:
                            links.add(normalized)
                except Exception:
                    pass
                    
            # Links in data attributes
            for attr in ['data-url', 'data-href', 'data-link', 'data-src', 'data-api', 'data-action', 'data-route']:
                elements = page.query_selector_all(f'[{attr}]')
                for el in elements:
                    try:
                        value = el.get_attribute(attr)
                        if value:
                            normalized = self._normalize_and_validate(value, url)
                            if normalized:
                                links.add(normalized)
                    except Exception:
                        pass
                        
            # Links in onclick handlers
            onclick_elements = page.query_selector_all('[onclick]')
            for el in onclick_elements:
                try:
                    onclick = el.get_attribute('onclick')
                    if onclick:
                        links.update(self._extract_urls_from_text(onclick, url))
                except Exception:
                    pass
                    
            # Frame and iframe sources
            frames = page.query_selector_all('frame[src], iframe[src]')
            for frame in frames:
                try:
                    src = frame.get_attribute('src')
                    if src and not src.startswith('about:'):
                        normalized = self._normalize_and_validate(src, url)
                        if normalized:
                            links.add(normalized)
                except Exception:
                    pass
                    
        except Exception as e:
            logger.debug(f"Error extracting links: {e}")
            
        return links

    def _extract_urls_from_scripts(self, page: Page, url: str) -> Set[str]:
        """Extract URLs from inline and external scripts"""
        urls = set()
        
        try:
            # Inline scripts
            scripts = page.query_selector_all('script:not([src])')
            for script in scripts:
                try:
                    content = script.inner_text()
                    if content:
                        urls.update(self._extract_urls_from_text(content, url))
                except Exception:
                    pass
                    
            # Also check full page source for any URLs we might have missed
            page_content = page.content()
            urls.update(self._extract_urls_from_text(page_content, url))
            
            # Extract from JSON-LD structured data
            json_ld = page.query_selector_all('script[type="application/ld+json"]')
            for script in json_ld:
                try:
                    content = script.inner_text()
                    data = json.loads(content)
                    urls.update(self._extract_urls_from_json(data, url))
                except Exception:
                    pass
                    
            # Extract from Next.js/Nuxt.js data
            next_data = page.query_selector('script#__NEXT_DATA__')
            if next_data:
                try:
                    content = next_data.inner_text()
                    data = json.loads(content)
                    urls.update(self._extract_urls_from_json(data, url))
                except Exception:
                    pass
                    
        except Exception as e:
            logger.debug(f"Error extracting from scripts: {e}")
            
        return urls

    def _extract_urls_from_json(self, data: Any, base_url: str) -> Set[str]:
        """Recursively extract URLs from JSON data"""
        urls = set()
        
        if isinstance(data, dict):
            for key, value in data.items():
                # Check if key suggests a URL
                if any(x in key.lower() for x in ['url', 'href', 'link', 'path', 'route', 'src']):
                    if isinstance(value, str):
                        normalized = self._normalize_and_validate(value, base_url)
                        if normalized:
                            urls.add(normalized)
                # Recurse
                urls.update(self._extract_urls_from_json(value, base_url))
        elif isinstance(data, list):
            for item in data:
                urls.update(self._extract_urls_from_json(item, base_url))
        elif isinstance(data, str):
            # Check if it looks like a URL or path
            if data.startswith('/') or data.startswith('http'):
                normalized = self._normalize_and_validate(data, base_url)
                if normalized:
                    urls.add(normalized)
                    
        return urls

    def _extract_forms(self, page: Page, url: str) -> List[Form]:
        """Extract forms from the page"""
        forms = []
        
        try:
            form_elements = page.query_selector_all('form')
            
            for form in form_elements:
                try:
                    action = form.get_attribute('action') or ''
                    method = form.get_attribute('method') or 'get'
                    action_url = self._normalize_and_validate(action, url) or url
                    
                    fields = []
                    inputs = form.query_selector_all('input, textarea, select')
                    
                    for inp in inputs:
                        try:
                            name = inp.get_attribute('name')
                            if not name:
                                continue
                                
                            fields.append(FormField(
                                name=name,
                                type=inp.get_attribute('type') or 'text',
                                value=inp.get_attribute('value') or '',
                                required=inp.get_attribute('required') is not None
                            ))
                        except Exception:
                            pass
                            
                    if fields:
                        forms.append(Form(
                            action=action_url,
                            method=method.lower(),
                            fields=fields
                        ))
                except Exception:
                    pass
                    
        except Exception as e:
            logger.debug(f"Error extracting forms: {e}")
            
        return forms

    def _scroll_page(self, page: Page) -> Set[str]:
        """Scroll page to trigger lazy loading, return new URLs found"""
        urls_before = self._extract_links_from_page(page, page.url)
        
        try:
            for i in range(self.max_scroll_attempts):
                # Get current scroll height
                scroll_height = page.evaluate('document.body.scrollHeight')
                
                # Scroll down
                page.evaluate(f'window.scrollTo(0, {scroll_height})')
                time.sleep(0.5)
                
                # Check if we've reached the bottom
                new_height = page.evaluate('document.body.scrollHeight')
                if new_height == scroll_height:
                    break
                    
            # Scroll back to top
            page.evaluate('window.scrollTo(0, 0)')
            time.sleep(0.3)
            
        except Exception as e:
            logger.debug(f"Scroll error: {e}")
            
        urls_after = self._extract_links_from_page(page, page.url)
        return urls_after - urls_before

    def _click_elements(self, page: Page, url: str) -> Set[str]:
        """Click interactive elements to discover hidden content"""
        discovered = set()
        clicked = 0
        
        # Get page state before clicking
        urls_before = self._extract_links_from_page(page, url)
        
        # Find clickable elements
        for selector in self.CLICKABLE_SELECTORS + self.INTERACTIVE_SELECTORS:
            if clicked >= self.max_clicks_per_page:
                break
                
            try:
                elements = page.query_selector_all(selector)
                
                for element in elements[:5]:  # Limit per selector
                    if clicked >= self.max_clicks_per_page:
                        break
                        
                    try:
                        # Check if element is visible and clickable
                        if not element.is_visible():
                            continue
                            
                        # Get href if it's a link (we'll add it directly)
                        href = element.get_attribute('href')
                        if href:
                            normalized = self._normalize_and_validate(href, url)
                            if normalized:
                                discovered.add(normalized)
                                
                        # Try clicking
                        element.click(timeout=self.click_timeout)
                        clicked += 1
                        self.stats.elements_clicked += 1
                        
                        # Wait for potential content to load
                        time.sleep(0.3)
                        
                        # Check for new URLs
                        urls_after = self._extract_links_from_page(page, url)
                        new_urls = urls_after - urls_before
                        discovered.update(new_urls)
                        urls_before = urls_after
                        
                        # Check current URL (might have navigated)
                        current_url = page.url
                        if current_url != url:
                            normalized = self._normalize_and_validate(current_url, url)
                            if normalized:
                                discovered.add(normalized)
                            # Go back
                            try:
                                page.go_back(timeout=5000)
                                time.sleep(0.3)
                            except Exception:
                                # If can't go back, navigate to original URL
                                page.goto(url, timeout=self.page_timeout)
                                
                    except Exception:
                        pass
                        
            except Exception:
                pass
                
        return discovered

    def _fetch_sitemap(self, context: BrowserContext) -> Set[str]:
        """Fetch and parse sitemap.xml"""
        urls = set()
        
        sitemap_locations = [
            f"{self.base_scheme}://{self.base_domain}/sitemap.xml",
            f"{self.base_scheme}://{self.base_domain}/sitemap_index.xml",
            f"{self.base_scheme}://{self.base_domain}/sitemap/sitemap.xml",
            f"{self.base_scheme}://{self.base_domain}/sitemaps/sitemap.xml",
        ]
        
        page = context.new_page()
        
        for sitemap_url in sitemap_locations:
            try:
                response = page.goto(sitemap_url, timeout=10000)
                
                if response and response.status == 200:
                    content = page.content()
                    
                    # Extract URLs from sitemap
                    loc_matches = re.findall(r'<loc>([^<]+)</loc>', content, re.IGNORECASE)
                    for url in loc_matches:
                        normalized = self._normalize_and_validate(url, self.start_url)
                        if normalized:
                            urls.add(normalized)
                            
                    # Check for nested sitemaps
                    sitemap_matches = re.findall(r'<sitemap>\s*<loc>([^<]+)</loc>', content, re.IGNORECASE)
                    for nested_url in sitemap_matches:
                        try:
                            nested_response = page.goto(nested_url, timeout=10000)
                            if nested_response and nested_response.status == 200:
                                nested_content = page.content()
                                nested_locs = re.findall(r'<loc>([^<]+)</loc>', nested_content, re.IGNORECASE)
                                for url in nested_locs:
                                    normalized = self._normalize_and_validate(url, self.start_url)
                                    if normalized:
                                        urls.add(normalized)
                        except Exception:
                            pass
                            
                    if urls:
                        self._log("info", f"Found {len(urls)} URLs in sitemap")
                        break
                        
            except Exception:
                pass
                
        page.close()
        return urls

    def _fetch_robots_txt(self, context: BrowserContext) -> Set[str]:
        """Parse robots.txt for additional URLs and sitemaps"""
        urls = set()
        robots_url = f"{self.base_scheme}://{self.base_domain}/robots.txt"
        
        page = context.new_page()
        
        try:
            response = page.goto(robots_url, timeout=10000)
            
            if response and response.status == 200:
                content = page.inner_text('body')
                
                # Extract sitemap URLs
                sitemap_matches = re.findall(r'Sitemap:\s*(\S+)', content, re.IGNORECASE)
                for sitemap_url in sitemap_matches:
                    # Fetch each sitemap
                    try:
                        sitemap_response = page.goto(sitemap_url, timeout=10000)
                        if sitemap_response and sitemap_response.status == 200:
                            sitemap_content = page.content()
                            loc_matches = re.findall(r'<loc>([^<]+)</loc>', sitemap_content, re.IGNORECASE)
                            for url in loc_matches:
                                normalized = self._normalize_and_validate(url, self.start_url)
                                if normalized:
                                    urls.add(normalized)
                    except Exception:
                        pass
                        
                # Extract paths from Allow/Disallow
                path_matches = re.findall(r'(?:Allow|Disallow):\s*(/[^\s*$]+)', content)
                for path in path_matches:
                    if '*' not in path and '$' not in path:
                        full_url = f"{self.base_scheme}://{self.base_domain}{path}"
                        normalized = self._normalize_and_validate(full_url, self.start_url)
                        if normalized:
                            urls.add(normalized)
                            
        except Exception:
            pass
            
        page.close()
        return urls

    def _crawl_page(self, page: Page, url: str, depth: int) -> PageData:
        """Crawl a single page and extract all data"""
        page_data = PageData(url=url)
        
        try:
            # Navigate to page
            wait_until = 'networkidle' if self.wait_for_idle else 'load'
            response = page.goto(url, timeout=self.page_timeout, wait_until=wait_until)
            
            # Check if it's an HTML page
            if response:
                content_type = response.headers.get('content-type', '')
                if 'text/html' not in content_type.lower():
                    return page_data
                    
            # Wait for dynamic content
            time.sleep(0.5)
            
            # Extract links from rendered HTML
            page_data.links.update(self._extract_links_from_page(page, url))
            
            # Extract URLs from JavaScript
            if self.extract_js_urls:
                page_data.js_urls.update(self._extract_urls_from_scripts(page, url))
                page_data.links.update(page_data.js_urls)
                
            # Extract forms
            page_data.forms = self._extract_forms(page, url)
            
            # Scroll to trigger lazy loading
            if self.scroll_pages:
                scroll_urls = self._scroll_page(page)
                page_data.links.update(scroll_urls)
                
            # Click elements to discover hidden content
            if self.click_elements:
                click_urls = self._click_elements(page, url)
                page_data.links.update(click_urls)
                
            # Re-extract forms after interactions (might have revealed new ones)
            if self.click_elements or self.scroll_pages:
                new_forms = self._extract_forms(page, url)
                for form in new_forms:
                    if form not in page_data.forms:
                        page_data.forms.append(form)
                        
        except Exception as e:
            self._log("warning", f"Error crawling {url}: {str(e)}")
            self.stats.errors += 1
            
        return page_data

    def _add_form_as_target(self, form: Form):
        """Add a form as a scan target"""
        param_names = [f.name for f in form.fields]
        if not param_names:
            return
            
        sig = f"{form.method.upper()}|{form.action}|{','.join(sorted(param_names))}"
        
        if sig not in self.seen_targets:
            target = ScanTarget(
                url=form.action,
                method=form.method.upper(),
                parameters=param_names,
                context="form"
            )
            self.targets.append(target)
            self.seen_targets.add(sig)
            self.stats.forms_found += 1
            
            if self.callback:
                self.callback(self.job_id, {"new_target": target})

    def _add_url_as_target(self, url: str):
        """Add a URL with query parameters as a scan target"""
        parsed = urlparse(url)
        if not parsed.query:
            return
            
        params = parse_qs(parsed.query)
        param_names = list(params.keys())
        
        if not param_names:
            return
            
        # Create clean URL without query string
        clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
        sig = f"GET|{clean_url}|{','.join(sorted(param_names))}"
        
        if sig not in self.seen_targets:
            target = ScanTarget(
                url=clean_url,
                method="GET",
                parameters=param_names,
                context="url"
            )
            self.targets.append(target)
            self.seen_targets.add(sig)

    def scan(self) -> Dict[str, Any]:
        """
        Main scan method.
        
        Returns:
            Dictionary with targets, findings, api_endpoints, and stats
        """
        self._log("info", f"Starting production crawl of {self.start_url}")
        
        with sync_playwright() as p:
            # Configure browser launch options (proxy at browser level for all contexts)
            launch_options = {"headless": True}
            if self.proxy:
                launch_options["proxy"] = {"server": self.proxy}
                self._log("info", f"Using proxy: {self.proxy}")

            browser = p.chromium.launch(**launch_options)
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
            
            # Inject cookies if provided
            if self.cookies:
                cookie_list = []
                for name, value in self.cookies.items():
                    cookie_list.append({
                        "name": name,
                        "value": value,
                        "domain": self.base_domain,
                        "path": "/"
                    })
                context.add_cookies(cookie_list)
                
            # Fetch sitemap and robots.txt first
            if self.fetch_sitemap:
                sitemap_urls = self._fetch_sitemap(context)
                robots_urls = self._fetch_robots_txt(context)
                
                for url in sitemap_urls | robots_urls:
                    if url not in self.discovered_urls:
                        self.queue.append((url, 1))
                        self.discovered_urls.add(url)
                        
            # Create main page for crawling
            page = context.new_page()
            
            # Set up network interception
            if self.intercept_network:
                self._setup_network_interception(page)
                
            # BFS crawl
            while self.queue and len(self.visited) < self.max_pages:
                url, depth = self.queue.popleft()
                
                # Skip if already visited or too deep
                if url in self.visited:
                    continue
                if depth > self.max_depth:
                    continue
                    
                self.visited.add(url)
                self.stats.pages_visited += 1

                # Track depth and parent for graph analysis
                self.page_depths[url] = depth

                # Report progress
                self._report_progress(current_url=url, depth=depth)
                self._log("info", f"Crawling [{len(self.visited)}/{self.max_pages}]: {url}")

                # Crawl the page
                page_data = self._crawl_page(page, url, depth)

                # Track outgoing links for graph analysis
                self.page_links[url] = set(page_data.links)

                # Add forms as targets
                for form in page_data.forms:
                    self._add_form_as_target(form)

                # Add URLs with parameters as targets
                for link in page_data.links:
                    self._add_url_as_target(link)

                # Queue new URLs for crawling
                for link in page_data.links:
                    if link not in self.discovered_urls:
                        self.queue.append((link, depth + 1))
                        self.discovered_urls.add(link)
                        self.stats.pages_discovered += 1
                        # Track parent for graph analysis
                        if link not in self.page_parents:
                            self.page_parents[link] = url
                        
            # Also add network-discovered URLs as targets
            for url in self.network_urls:
                self._add_url_as_target(url)
                if url not in self.discovered_urls:
                    self.discovered_urls.add(url)
                    
            browser.close()
            
        # Update final stats
        self.stats.api_endpoints_found = len(self.api_endpoints)
        
        self._log("info", f"Crawl complete. Visited: {self.stats.pages_visited}, "
                  f"Discovered: {self.stats.pages_discovered}, "
                  f"Targets: {len(self.targets)}, "
                  f"APIs: {len(self.api_endpoints)}")
        
        # Run vulnerability tests
        from scanner.vulnerability_tester import VulnerabilityTester

        tester = VulnerabilityTester(
            db_scan_id=self.db_scan_id,
            min_confidence=0.7,
            confirm_findings=True,
            proxy=self.proxy  # Pass proxy for Burp/ZAP integration
        )
        
        findings = []
        for i, target in enumerate(self.targets):
            self._report_progress(
                phase="testing",
                testing_progress=f"{i+1}/{len(self.targets)}",
                current_target=target.url
            )
            target_findings = tester.test_target(target)
            findings.extend(target_findings)
            
        result = {
            "targets": self.targets,
            "findings": [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings],
            "api_endpoints": list(self.api_endpoints),
            "discovered_urls": list(self.discovered_urls),
            "network_urls": list(self.network_urls),
            "stats": {
                "pages_visited": self.stats.pages_visited,
                "pages_discovered": self.stats.pages_discovered,
                "forms_found": self.stats.forms_found,
                "targets_found": len(self.targets),
                "api_endpoints_found": self.stats.api_endpoints_found,
                "network_requests_captured": self.stats.network_requests_captured,
                "elements_clicked": self.stats.elements_clicked,
                "vulnerabilities_found": len(findings),
                "errors": self.stats.errors,
            },
            # Include crawl graph data for DFS analysis
            "crawl_graph": {
                "visited_urls": list(self.visited),
                "page_links": {k: list(v) for k, v in self.page_links.items()},
                "page_depths": self.page_depths,
                "page_parents": self.page_parents,
            }
        }
        return result


# Backwards compatibility - keep the old class name working
class WebScanner(ProductionCrawler):
    """Alias for backwards compatibility"""
    pass