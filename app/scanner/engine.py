import requests
from collections import deque
from urllib.parse import urlparse

from scanner.models import ScanTarget
from scanner.extractor import extract_links, extract_forms
from scanner.scope import is_in_scope, normalize_url


class WebScanner:
    def __init__(self, url: str, max_pages: int = 100):
        self.start_url = normalize_url(url)
        self.max_pages = max_pages
        self.visited = set()
        self.queue = deque([self.start_url])
        self.targets: list[ScanTarget] = []

    def scan(self) -> list[ScanTarget]:
        while self.queue and len(self.visited) < self.max_pages:
            url = self.queue.popleft()
            url = normalize_url(url)

            if url in self.visited:
                continue

            try:
                response = requests.get(url, timeout=5)
                if "text/html" not in response.headers.get("Content-Type", ""):
                    continue
            except Exception:
                continue

            self.visited.add(url)
            html = response.text

            parsed = urlparse(url)
            if parsed.query:
                params = [p.split("=")[0] for p in parsed.query.split("&")]
                self.targets.append(ScanTarget(
                    url=url,
                    method="GET",
                    parameters=params,
                    context="url"
                ))

            for form in extract_forms(html, url):
                self.targets.append(ScanTarget(
                    url=form.action,
                    method=form.method.upper(),
                    parameters=[f.name for f in form.fields],
                    context="form"
                ))

            for link in extract_links(html, url):
                if is_in_scope(self.start_url, link):
                    self.queue.append(link)

        return self.targets
