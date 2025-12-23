from fastapi import APIRouter, Request
from scanner.engine import WebScanner
from scanner.models import ScanTarget
from typing import List

router = APIRouter(tags=["scanner"])

@router.post("/", response_model=List[ScanTarget])
def start_scan(
    url: str,
    max_pages: int = 30,
    request: Request = None
):
    user = request.state.user  # injected by middleware

    scanner = WebScanner(
        url=url,
        max_pages=max_pages
    )

    return scanner.scan()
