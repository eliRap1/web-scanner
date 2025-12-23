from dataclasses import dataclass
from typing import List


@dataclass
class FormField:
    name: str
    type: str
    required: bool


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
