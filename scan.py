import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

session = requests.Session()
session.headers["User-Agent"] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


def get_forms(url):
    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(f"[ERROR] Unable to retrieve forms: {e}")
        return []


def get_form_details(form):
    return {
        "action": form.attrs.get("action", ""),
        "method": form.attrs.get("method", "get").lower(),
        "inputs": [
            {
                "type": tag.attrs.get("type", "text"),
                "name": tag.attrs.get("name"),
                "value": tag.attrs.get("value", "")
            }
            for tag in form.find_all("input")
        ]
    }


def detect_sql_error(response_text):
    errors = [
        "quoted string not properly terminated",
        "unclosed quotation mark",
        "you have an error in your sql syntax",
        "mysql_fetch",
        "warning: mysql",
        "sql syntax",
        "mysql_num_rows",
        "ora-01756",
        "odbc sql server driver"
    ]

    text = response_text.lower()
    return any(err in text for err in errors)


def scan_url(url):
    print(f"\n[+] Scanning: {url}")

    forms = get_forms(url)
    print(f"[+] Found {len(forms)} forms")

    vulnerability_found = False

    for index, form in enumerate(forms, start=1):
        details = get_form_details(form)
        target_url = urljoin(url, details["action"])

        print(f"\n[+] Testing Form #{index}")
        print(f"    Action: {target_url}")
        print(f"    Method: {details['method'].upper()}")

        for payload in ["'", '"']:

            data = {}

            for field in details["inputs"]:
                name = field.get("name")
                if not name:
                    continue

                if field["type"] == "hidden":
                    data[name] = field["value"] + payload
                elif field["type"] != "submit":
                    data[name] = "test" + payload

            try:
                if details["method"] == "post":
                    response = session.post(target_url, data=data, timeout=10)
                else:
                    response = session.get(target_url, params=data, timeout=10)

                if detect_sql_error(response.text):
                    vulnerability_found = True

                    print("\n[!] ALERT: Possible SQL Injection Detected")
                    print(f"    URL: {target_url}")
                    print(f"    Payload: {payload}")
                    print(f"    Data: {data}")
                    print("-" * 60)

                    break

            except Exception as e:
                print(f"[ERROR] Request failed: {e}")

    # FINAL RESULT
    print("\nRESULT......")
    if vulnerability_found:
        print("[!] ALERT: SQL Injection vulnerability detected!")
    else:
        print("[✓] SQL injection is not found")


if __name__ == "__main__":
    target = input("Enter target URL: ").strip()
    scan_url(target)


