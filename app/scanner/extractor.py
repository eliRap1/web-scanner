from bs4 import BeautifulSoup
from urllib.parse import urljoin
from scanner.models import Form, FormField


def extract_links(html: str, base_url: str) -> set[str]:
    soup = BeautifulSoup(html, "html.parser")
    links = set()

    for tag in soup.find_all("a", href=True):
        links.add(urljoin(base_url, tag["href"]))

    return links


def extract_forms(html: str, base_url: str) -> list[Form]:
    soup = BeautifulSoup(html, "html.parser")
    forms = []

    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        action_url = urljoin(base_url, action)

        fields = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue

            fields.append(FormField(
                name=name,
                type=inp.get("type", "text"),
                value=inp.get("value", ""), 
                required=inp.has_attr("required")
            ))

        forms.append(Form(
            action=action_url,
            method=method,
            fields=fields
        ))

    return forms
