#!/usr/bin/env python3
import time
import requests
import sys

BACKEND_URL = "http://localhost:8000"
MAX_RETRIES = 60
RETRY_DELAY = 1

def check_backend_health():
    print(f"Waiting for backend to be ready at {BACKEND_URL}...", end="")
    sys.stdout.flush()
    for i in range(MAX_RETRIES):
        try:
            response = requests.get(f"{BACKEND_URL}/health", timeout=2)
            if response.status_code == 200:
                print("\nBackend is healthy!")
                return True
        except requests.exceptions.RequestException:
            pass

        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(RETRY_DELAY)

    print("\nTimeout: Backend did not become ready in time.")
    return False

def check_apis():
    print("Checking external APIs status...\n")
    try:
        response = requests.get(f"{BACKEND_URL}/api/status?force=true", timeout=15)
        if response.status_code == 200:
            data = response.json()

            print("-" * 50)
            print("API CONFIGURATION & HEALTH REPORT")
            print("-" * 50)

            for api_name, api_data in data.items():
                if api_name == "_last_checked":
                    continue

                display_name = {
                    "virustotal": "VirusTotal",
                    "malwarebazaar": "MalwareBazaar",
                    "urlscan": "urlscan.io",
                    "neiki": "Neiki TIP"
                }.get(api_name, api_name)

                # We need to make sure api_data is a dictionary, since _last_checked might slip in if not caught
                if not isinstance(api_data, dict):
                    continue

                connected = api_data.get("connected", False)
                message = api_data.get("message", "Unknown status")

                status_icon = "✅" if connected else "❌"
                print(f"{status_icon} {display_name}: {message}")

            print("-" * 50)
        else:
            print(f"Failed to fetch API status. HTTP {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error checking API status: {e}")

if __name__ == "__main__":
    if check_backend_health():
        check_apis()
    else:
        sys.exit(1)
