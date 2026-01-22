"""
scanner/http_client.py

HTTP client utilities for making authenticated requests during vulnerability testing.
Improved version with:
- Smart request handling (GET params vs POST data)
- Retry logic with backoff
- Timeout handling
- Rate limiting awareness
"""

import time
import logging
import warnings
from typing import Optional, Dict, Any
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
import requests
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings - expected for security scanner testing sites with invalid certs
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

logger = logging.getLogger(__name__)

# Configuration
DEFAULT_TIMEOUT = 5  # Shorter timeout for faster scanning
MAX_RETRIES = 1      # Only 1 retry to speed things up
RETRY_BACKOFF = 0.5
RATE_LIMIT_DELAY = 0.05  # Small delay between requests


def smart_request(
    session: Optional[requests.Session],
    url: str,
    method: str = "GET",
    params: Optional[Dict[str, str]] = None,
    data: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
    follow_redirects: bool = True
) -> requests.Response:
    """
    Make an intelligent HTTP request based on method type.
    
    For GET: adds params to URL query string
    For POST: sends params as form data
    For other methods: sends as appropriate
    
    Args:
        session: requests.Session object (creates new if None)
        url: Target URL
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        params: Parameters to send (query params for GET, form data for POST)
        data: Raw body data (overrides params for POST if both provided)
        headers: Additional headers
        timeout: Request timeout in seconds
        follow_redirects: Whether to follow redirects
        
    Returns:
        requests.Response object
        
    Raises:
        requests.RequestException on failure after retries
    """
    if session is None:
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'WebScanner/1.0 (Security Testing)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })

    method = method.upper()
    last_error = None
    
    for attempt in range(MAX_RETRIES + 1):
        try:
            # Rate limiting
            time.sleep(RATE_LIMIT_DELAY)
            
            response = _make_request(
                session=session,
                url=url,
                method=method,
                params=params,
                data=data,
                headers=headers,
                timeout=timeout,
                follow_redirects=follow_redirects
            )
            
            return response
            
        except requests.Timeout:
            last_error = f"Request timeout after {timeout}s"
            logger.warning(f"Attempt {attempt + 1}: {last_error} for {url}")
            
        except requests.ConnectionError as e:
            last_error = f"Connection error: {str(e)[:100]}"
            logger.warning(f"Attempt {attempt + 1}: {last_error} for {url}")
            
        except requests.RequestException as e:
            last_error = f"Request error: {str(e)[:100]}"
            logger.warning(f"Attempt {attempt + 1}: {last_error} for {url}")
        
        # Exponential backoff before retry
        if attempt < MAX_RETRIES:
            sleep_time = RETRY_BACKOFF * (2 ** attempt)
            time.sleep(sleep_time)
    
    # All retries failed - raise exception
    raise requests.RequestException(f"Failed after {MAX_RETRIES + 1} attempts: {last_error}")


def _make_request(
    session: requests.Session,
    url: str,
    method: str,
    params: Optional[Dict[str, str]],
    data: Optional[Dict[str, Any]],
    headers: Optional[Dict[str, str]],
    timeout: int,
    follow_redirects: bool
) -> requests.Response:
    """Internal function to make a single request."""
    
    request_kwargs = {
        "timeout": timeout,
        "allow_redirects": follow_redirects,
        "verify": False  # For testing - might encounter self-signed certs
    }
    
    if headers:
        request_kwargs["headers"] = headers

    if method == "GET":
        # For GET, add params to URL query string
        if params:
            request_kwargs["params"] = params
        response = session.get(url, **request_kwargs)
        
    elif method == "POST":
        # For POST, send as form data
        if data:
            request_kwargs["data"] = data
        elif params:
            request_kwargs["data"] = params
        response = session.post(url, **request_kwargs)
        
    elif method == "PUT":
        if data:
            request_kwargs["data"] = data
        elif params:
            request_kwargs["data"] = params
        response = session.put(url, **request_kwargs)
        
    elif method == "DELETE":
        if params:
            request_kwargs["params"] = params
        response = session.delete(url, **request_kwargs)
        
    elif method == "PATCH":
        if data:
            request_kwargs["data"] = data
        elif params:
            request_kwargs["data"] = params
        
        try:
            response = session.patch(url, **request_kwargs)
        except Exception:
            # Fallback: Use POST with X-HTTP-Method-Override
            request_kwargs["headers"] = request_kwargs.get("headers", {})
            request_kwargs["headers"]["X-HTTP-Method-Override"] = "PATCH"
            response = session.post(url, **request_kwargs)
    else:
        # Generic request for other methods
        response = session.request(method, url, **request_kwargs)

    return response


def build_url_with_params(base_url: str, params: Dict[str, str]) -> str:
    """
    Build a URL with query parameters properly encoded.
    
    Args:
        base_url: Base URL (may already have query params)
        params: Parameters to add/update
        
    Returns:
        URL with parameters
    """
    parsed = urlparse(base_url)
    
    # Get existing query params
    existing_params = parse_qs(parsed.query)
    
    # Flatten existing params (parse_qs returns lists)
    flat_params = {k: v[0] if len(v) == 1 else v for k, v in existing_params.items()}
    
    # Update with new params
    flat_params.update(params)
    
    # Build new URL
    new_query = urlencode(flat_params, doseq=True)
    new_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))
    
    return new_url


# Legacy function for backward compatibility
def scan(session, url, method="GET", params=None, data=None, headers=None):
    """
    Legacy function - use smart_request instead.
    Kept for backward compatibility.
    """
    return smart_request(
        session=session,
        url=url,
        method=method,
        params=params,
        data=data,
        headers=headers
    )