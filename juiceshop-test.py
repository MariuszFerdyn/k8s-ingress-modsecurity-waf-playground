import requests

JUICESHOP_URL = "http://your-juice-shop-url"

# Define a list of attack test cases with method, endpoint, and payload
attack_tests = [
    # Reflected XSS (GET)
    {
        "name": "Reflected XSS",
        "method": "GET",
        "url": f"{JUICESHOP_URL}/#/track-result",
        "params": {"id": '<iframe src="javascript:alert(\'XSS\')">'},
    },
    # Stored XSS (POST)
    {
        "name": "Stored XSS",
        "method": "POST",
        "url": f"{JUICESHOP_URL}/api/Feedbacks",
        "json": {
            "comment": "<script>alert('Stored XSS')</script>",
            "rating": 5,
            "productId": 1
        },
    },
    # SQL Injection (GET)
    {
        "name": "SQL Injection",
        "method": "GET",
        "url": f"{JUICESHOP_URL}/rest/products/search",
        "params": {
            "q": "qwert')) UNION SELECT id,email,password,'4','5','6','7','8','9' FROM Users--"
        },
    },
    # NoSQL Injection (POST)
    {
        "name": "NoSQL Injection",
        "method": "POST",
        "url": f"{JUICESHOP_URL}/api/Users/login",
        "json": {
            "email": {"$ne": None},
            "password": {"$ne": None}
        },
    },
    # Server-Side Template Injection (SSTi) (POST)
    {
        "name": "SSTi",
        "method": "POST",
        "url": f"{JUICESHOP_URL}/api/Feedbacks",
        "json": {
            "comment": "{{7*7}}",
            "rating": 5,
            "productId": 1
        },
    },
    # XXE Attack (POST)
    {
        "name": "XXE",
        "method": "POST",
        "url": f"{JUICESHOP_URL}/api/xmlEndpoint",  # hypothetical endpoint for XML processing
        "headers": {"Content-Type": "application/xml"},
        "data": """<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>"""
    },
]

def test_attack(test):
    print(f"Testing: {test['name']}")
    try:
        if test["method"] == "GET":
            response = requests.get(test["url"], params=test.get("params", {}), timeout=10)
        elif test["method"] == "POST":
            headers = test.get("headers", {"Content-Type": "application/json"})
            if headers.get("Content-Type") == "application/json":
                response = requests.post(test["url"], json=test.get("json", {}), headers=headers, timeout=10)
            else:
                response = requests.post(test["url"], data=test.get("data", ""), headers=headers, timeout=10)
        else:
            print(f"Unsupported method {test['method']}")
            return

        print(f"Response code: {response.status_code}")

        # Basic WAF block detection heuristics
        if response.status_code in [403, 406, 429]:
            print("Likely blocked by WAF (HTTP status code)")
        elif "waf" in response.text.lower() or "blocked" in response.text.lower():
            print("Likely blocked by WAF (response content)")
        else:
            print("Request allowed or no clear WAF block detected")

    except Exception as e:
        print(f"Error during test: {e}")

if __name__ == "__main__":
    for attack in attack_tests:
        test_attack(attack)
        print("-" * 60)
