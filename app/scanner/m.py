import json
from scanner.engine import WebScanner

OUTPUT_FILE = "results.json"


def main():
    target_url = "https://www.hackthissite.org/"

    scanner = WebScanner(
        start_url=target_url,
        max_pages=50
    )

    results = scanner.scan()

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump([r.__dict__ for r in results], f, indent=2)

    print(f"[+] Scan completed")
    print(f"[+] Targets found: {len(results)}")
    print(f"[+] Results saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
