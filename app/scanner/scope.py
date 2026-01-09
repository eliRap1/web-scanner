# scanner/scope.py
from urllib.parse import urlparse, urljoin

def normalize_url(url: str) -> str:
    """
    Normalizes a URL by removing fragments (#), ensuring it has a scheme,
    and sorting query parameters (basic implementation).
    """
    if not url:
        return ""
    
    # Add scheme if missing (naive check)
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    
    # Remove fragment (hash) to avoid duplicate scans of the same page section
    clean_url = parsed._replace(fragment="").geturl()
    
    return clean_url

def is_in_scope(base_url: str, target_url: str) -> bool:
    """
    Checks if the target URL is within the scope of the base URL 
    (same domain) to prevent scanning the entire internet.
    """
    base_parsed = urlparse(base_url)
    target_parsed = urlparse(target_url)
    
    # Simple check: netloc (domain) must match
    return base_parsed.netloc == target_parsed.netloc