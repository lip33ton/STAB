import requests
import argparse
from list import Request, choosing_menu, run_sqli_scanner, run_xss_scanner
from crawler import crawl

headers = {
    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1"
}

import argparse
import requests

# Dummy headers just for example
headers = {
    "User-Agent": "STABScanner/1.0"
}

def main():
    parser = argparse.ArgumentParser(
        description="STAB - Save Time And Brain (Lip33ton's Offensive Web Scanner)",
        epilog="Example usage: python main.py --w "wordlist.txt" ( provide the location of the wordlist file if possible)
    )
    parser.add_argument(
        "--w",
        required=True,
        help="Path to directory brute-force wordlist (e.g. dirbuster.txt)"
    )
    args = parser.parse_args()

    website = input("Enter target (without https:// and .com): ").strip().lower()
    url = f"https://{website}.com"

    try:
        response = requests.get(url, headers=headers, timeout=10)
    except Exception as e:
        print(f"❌ Error fetching site: {e}")
        return

    # ✅ Now you can safely create your request_obj
    request_obj = Request()

    # Ask for crawl at start
    crawl_choice = input("Do you want to crawl the site first? (y/n): ").strip().lower()
    if crawl_choice == 'y':
        crawl(url, args.w, request_obj, run_sqli_scanner, run_xss_scanner)

    request_obj.traffic_interception(response)

    while True:
        choosing_menu(request_obj, response, url, args.w)


if __name__ == "__main__":
    main()
