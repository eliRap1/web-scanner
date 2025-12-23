from urllib.parse import urlparse


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed._replace(fragment="").geturl()


def is_in_scope(base_url: str, target_url: str) -> bool:
    return urlparse(base_url).netloc == urlparse(target_url).netloc
