"""HTTP client utilities for making authenticated requests during vulnerability testing"""
import requests


def scan(session, url, method="GET", params=None, data=None, headers=None):
    """
    Make an HTTP request with the provided session/parameters

    Args:
        session: requests.Session object (or None for unauthenticated)
        url: Target URL
        method: HTTP method (GET, POST, etc.)
        params: URL parameters (for GET) or form data (for POST)
        data: Request body data
        headers: Additional headers

    Returns:
        requests.Response object
    """
    if session is None:
        session = requests.Session()

    request_kwargs = {
        "timeout": 10,
        "allow_redirects": True
    }

    if headers:
        request_kwargs["headers"] = headers

    if method.upper() == "GET":
        if params:
            request_kwargs["params"] = params
        response = session.get(url, **request_kwargs)
    elif method.upper() == "POST":
        if params:
            request_kwargs["data"] = params
        if data:
            request_kwargs["data"] = data
        response = session.post(url, **request_kwargs)
    else:
        # Support other methods if needed
        response = session.request(method, url, **request_kwargs)

    return response
