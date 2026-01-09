from dataclasses import dataclass
from typing import List


@dataclass
class FormField:
    name: str
    type: str
    value: str = ""  # capture default values (CSRF tokens)
    required: bool = False


@dataclass
class Form:
    action: str
    method: str
    fields: List[FormField]


@dataclass
class ScanTarget:
    url: str
    method: str
    parameters: List[str]
    context: str  # "url" or "form"
