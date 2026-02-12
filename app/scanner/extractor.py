"""
Enhanced Link and Form Extractor

Improvements over basic extractor:
1. Extracts URLs from JavaScript code
2. Handles data attributes (data-url, data-href, etc.)
3. Discovers SPA routes from router configs
4. Extracts API endpoints from fetch/axios calls
"""

import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from scanner.models import Form, FormField


# Patterns for finding URLs in JavaScript
JS_URL_PATTERNS = [
    # Standard URL patterns in strings
    r'["\']((https?:)?//[^"\'<>\s]+)["\']',
    # Relative paths
    r'["\'](/[a-zA-Z0-9_\-./]+(?:\?[^"\'<>\s]*)?)["\']',
    # API endpoints in fetch/axios
    r'(?:fetch|axios|ajax|get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
    # Route definitions (React Router, Vue Router, Angular)
    r'path:\s*["\']([^"\']+)["\']',
    r'route:\s*["\']([^"\']+)["\']',
    # href and src in template literals
    r'href=`([^`]+)`',
    r'src=`([^`]+)`',
    # Data attributes with URLs
    r'data-(?:url|href|src|link|api)=["\']([^"\']+)["\']',
    # window.location patterns
    r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
    # Next.js/Nuxt patterns
    r'href=\{["\']([^"\']+)["\']\}',
    r'to=\{?["\']([^"\']+)["\']\}?',
]


def extract_urls_from_javascript(text: str, base_url: str) -> set[str]:
    """Extract URLs from JavaScript code"""
    urls = set()
    
    for pattern in JS_URL_PATTERNS:
        try:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                url = match[0] if isinstance(match, tuple) else match
                url = url.strip().strip('"\'')
                
                # Skip template literals with variables
                if '${' in url or '{{' in url or '{%' in url:
                    continue
                    
                # Skip obvious non-URLs
                if url.startswith(('javascript:', 'mailto:', 'tel:', 'data:', '#')):
                    continue
                    
                # Convert to absolute URL
                if url.startswith('//'):
                    parsed_base = urlparse(base_url)
                    url = f"{parsed_base.scheme}:{url}"
                elif not url.startswith(('http://', 'https://')):
                    url = urljoin(base_url, url)
                    
                urls.add(url)
        except Exception:
            pass
            
    return urls


def extract_links(page_or_html, base_url: str) -> set[str]:
    """
    Extract links from HTML content or Playwright Page.
    
    Now also extracts:
    - Links from onclick handlers
    - Links from data attributes
    - Links from inline JavaScript
    - SPA router routes
    """
    links = set()

    if isinstance(page_or_html, str):
        # --- BeautifulSoup Mode (for AuthManager / static HTML) ---
        soup = BeautifulSoup(page_or_html, "html.parser")
        
        # Standard anchor tags
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            if href and not href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                links.add(urljoin(base_url, href))
        
        # Links in onclick handlers
        for tag in soup.find_all(onclick=True):
            onclick = tag.get("onclick", "")
            links.update(extract_urls_from_javascript(onclick, base_url))
            
        # Data attributes with URLs
        for attr in ['data-url', 'data-href', 'data-link', 'data-src', 'data-api', 'data-action']:
            for tag in soup.find_all(attrs={attr: True}):
                url = tag.get(attr)
                if url:
                    links.add(urljoin(base_url, url))
                    
        # URLs in inline scripts
        for script in soup.find_all("script"):
            if script.string:
                links.update(extract_urls_from_javascript(script.string, base_url))
                
        # Meta refresh redirects
        for meta in soup.find_all("meta", attrs={"http-equiv": "refresh"}):
            content = meta.get("content", "")
            match = re.search(r'url=([^\s;]+)', content, re.IGNORECASE)
            if match:
                links.add(urljoin(base_url, match.group(1)))
                
        # Frame/iframe sources
        for tag in soup.find_all(['frame', 'iframe'], src=True):
            src = tag.get("src")
            if src and not src.startswith('about:'):
                links.add(urljoin(base_url, src))
    
    else:
        # --- Playwright Mode (for Scanner with JS rendering) ---
        # Standard anchor tags
        elements = page_or_html.query_selector_all("a[href]")
        for el in elements:
            href = el.get_attribute("href")
            if href and not href.startswith(('javascript:', 'mailto:', 'tel:')):
                links.add(urljoin(base_url, href))
        
        # Links in onclick handlers
        onclick_elements = page_or_html.query_selector_all("[onclick]")
        for el in onclick_elements:
            onclick = el.get_attribute("onclick")
            if onclick:
                links.update(extract_urls_from_javascript(onclick, base_url))
                
        # Data attributes with URLs
        for attr in ['data-url', 'data-href', 'data-link', 'data-src', 'data-api']:
            elements = page_or_html.query_selector_all(f"[{attr}]")
            for el in elements:
                url = el.get_attribute(attr)
                if url:
                    links.add(urljoin(base_url, url))
                    
        # URLs from inline scripts
        scripts = page_or_html.query_selector_all("script:not([src])")
        for script in scripts:
            try:
                content = script.inner_text()
                if content:
                    links.update(extract_urls_from_javascript(content, base_url))
            except Exception:
                pass
                
        # Also get the full page content for additional URL extraction
        try:
            page_content = page_or_html.content()
            # Extract routes from React/Vue/Angular router configs
            route_patterns = [
                r'<Route[^>]+path=["\']([^"\']+)["\']',
                r'path:\s*["\']([^"\']+)["\']',
                r'href:\s*["\']([^"\']+)["\']',
            ]
            for pattern in route_patterns:
                matches = re.findall(pattern, page_content)
                for match in matches:
                    if match.startswith('/'):
                        links.add(urljoin(base_url, match))
        except Exception:
            pass
            
    return links


def extract_forms(page_or_html, base_url: str) -> list[Form]:
    """
    Extract forms from HTML content or Playwright Page.
    """
    forms = []

    if isinstance(page_or_html, str):
        # --- BeautifulSoup Mode (for AuthManager) ---
        soup = BeautifulSoup(page_or_html, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            action_url = urljoin(base_url, action)

            fields = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue

                fields.append(FormField(
                    name=name,
                    type=inp.get("type", "text"),
                    value=inp.get("value", ""),
                    required=inp.has_attr("required")
                ))

            forms.append(Form(action=action_url, method=method, fields=fields))
    else:
        # --- Playwright Mode (for Scanner) ---
        form_elements = page_or_html.query_selector_all("form")

        for form in form_elements:
            action = form.get_attribute("action") or ""
            method = form.get_attribute("method") or "get"
            action_url = urljoin(base_url, action)

            fields = []
            input_elements = form.query_selector_all("input, textarea, select")
            
            for inp in input_elements:
                name = inp.get_attribute("name")
                if not name:
                    continue
                
                fields.append(FormField(
                    name=name,
                    type=inp.get_attribute("type") or "text",
                    value=inp.get_attribute("value") or "",
                    required=inp.get_attribute("required") is not None
                ))

            forms.append(Form(action=action_url, method=method.lower(), fields=fields))
        
    return forms


def extract_api_endpoints(page_or_html, base_url: str) -> set[str]:
    """
    Extract potential API endpoints from JavaScript code.
    
    Looks for patterns like:
    - fetch('/api/...')
    - axios.get('/v1/...')
    - baseURL: '/api'
    """
    endpoints = set()
    
    api_patterns = [
        r'["\']/(api|v[0-9]+|graphql|rest)/[a-zA-Z0-9_/\-]+["\']',
        r'(?:baseURL|apiUrl|endpoint|apiBase)\s*[:=]\s*["\']([^"\']+)["\']',
        r'fetch\s*\(\s*["\']([^"\']*(?:api|v[0-9])[^"\']*)["\']',
        r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
        r'\.(?:get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']',
    ]
    
    if isinstance(page_or_html, str):
        content = page_or_html
    else:
        try:
            content = page_or_html.content()
        except Exception:
            return endpoints
            
    for pattern in api_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for match in matches:
            url = match if isinstance(match, str) else match
            if url.startswith('/'):
                endpoints.add(urljoin(base_url, url))
            elif url.startswith(('http://', 'https://')):
                endpoints.add(url)
                
    return endpoints