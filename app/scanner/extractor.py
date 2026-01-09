from urllib.parse import urljoin
from bs4 import BeautifulSoup # We still need this for AuthManager
from scanner.models import Form, FormField

def extract_links(page_or_html, base_url: str) -> set[str]:
    """
    Handles extracting links from both Raw HTML (AuthManager) 
    and Playwright Pages (Scanner).
    """
    links = set()

    if isinstance(page_or_html, str):
        # --- BeautifulSoup Mode (for AuthManager) ---
        soup = BeautifulSoup(page_or_html, "html.parser")
        for tag in soup.find_all("a", href=True):
            links.add(urljoin(base_url, tag["href"]))
    
    else:
        # --- Playwright Mode (for Scanner) ---
        # page_or_html is assumed to be a Playwright Page object
        elements = page_or_html.query_selector_all("a")
        for el in elements:
            href = el.get_attribute("href")
            if href:
                links.add(urljoin(base_url, href))
            
    return links

def extract_forms(page_or_html, base_url: str) -> list[Form]:
    """
    Handles extracting forms from both Raw HTML and Playwright Pages.
    """
    forms = []

    if isinstance(page_or_html, str):
        # --- BeautifulSoup Mode (for AuthManager) ---
        soup = BeautifulSoup(page_or_html, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            action_url = urljoin(base_url, action)

            fields = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name: continue

                fields.append(FormField(
                    name=name,
                    type=inp.get("type", "text"),
                    value=inp.get("value", ""),
                    required=inp.has_attr("required")
                ))

            forms.append(Form(action=action_url, method=method, fields=fields))
    else:
        # --- Playwright Mode (for Scanner) ---
        form_elements = page_or_html.query_selector_all("form")

        for form in form_elements:
            action = form.get_attribute("action") or ""
            method = form.get_attribute("method") or "get"
            action_url = urljoin(base_url, action)

            fields = []
            input_elements = form.query_selector_all("input, textarea, select")
            
            for inp in input_elements:
                name = inp.get_attribute("name")
                if not name:
                    continue
                
                fields.append(FormField(
                    name=name,
                    type=inp.get_attribute("type") or "text",
                    # FIX 1: Use get_attribute instead of input_value for compatibility
                    value=inp.get_attribute("value") or "", 
                    # FIX 2: Check if "required" attribute exists
                    required=inp.get_attribute("required") is not None
                ))

            forms.append(Form(action=action_url, method=method.lower(), fields=fields))
        
    return forms