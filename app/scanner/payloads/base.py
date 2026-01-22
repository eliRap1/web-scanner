from dataclasses import dataclass
from typing import List, Callable

@dataclass
class Payload:
    vuln_type: str
    name: str
    payload: str
    contexts: List[str]          # url | form | header | json
    severity: str                # Low / Medium / High
    safe: bool                   # ethical flag
    confirmation: Callable[[str], bool]  # response analyzer
