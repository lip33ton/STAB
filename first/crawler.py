import requests
import time
import random
from pathlib import Path

user_agents = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.140 Mobile Safari/537.36"
]

headers = {
    "User-Agent": random.choice(user_agents)
}

visited_paths = set()

def crawl(base_url, wordlist_path, request_obj, sqli_func, xss_func, depth=0, max_depth=2):
    if depth > max_depth:
        return

    wordlist_path = Path(wordlist_path)
    if not wordlist_path.exists():
        print("❌ Wordlist not found.")
        return

    print(f"✅ Using existing wordlist from: {wordlist_path}")
    print("⚠️ Ignoring robots.txt for deep inspection...")

    with open(wordlist_path, "r") as f:
        words = [line.strip() for line in f if line.strip()]

    for word in words:
        word = word.strip("/").lower()
        full_url = f"{base_url.rstrip('/')}/{word}/"

        if full_url in visited_paths:
            continue
        visited_paths.add(full_url)

        try:
            res = requests.get(full_url, headers=headers, timeout=10)
            if res.status_code == 200:
                print(f"[200 OK] Found: {full_url}")

                request_obj.traffic_interception(res)
                request_obj.clickjacking(res)
                sqli_func(res)
                xss_func(res)

                with open("crawl_log.txt", "a") as log:
                    log.write(f"[200 OK] Found: {full_url}\n")

                crawl(full_url, wordlist_path, request_obj, sqli_func, xss_func, depth + 1, max_depth)
            else:
                print(f"[{res.status_code}] Skipped: {full_url}")
        except Exception as e:
            print(f"⚠️ Error checking {full_url}: {e}")

        time.sleep(0.1)