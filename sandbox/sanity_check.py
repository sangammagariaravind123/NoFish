import json
import os

import requests


API_BASE = os.environ.get("PHISHGUARD_API", "http://127.0.0.1:8000")
PREDICT_URL = f"{API_BASE}/predict"
DEEP_SCAN_URL = f"{API_BASE}/deep_scan"
TIMEOUT = 120

TEST_URLS = [
    "https://github.com",
    "https://google.com",
    "https://amazon.com",
    "https://wikipedia.org",
    "https://microsoft.com",
    "https://paypal-login-secure-example.xyz/verify",
    "http://192.168.0.1/login.php",
    "https://bit.ly/secure-login-check",
]


def call_api(endpoint: str, url: str) -> dict:
    response = requests.post(endpoint, json={"url": url}, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()


def main():
    print(f"Using API base: {API_BASE}\n")
    for url in TEST_URLS:
        print("=" * 90)
        print(url)
        try:
            predict_result = call_api(PREDICT_URL, url)
            deep_result = call_api(DEEP_SCAN_URL, url)

            print("L1+L2:")
            print(json.dumps(predict_result, indent=2))
            print("\nDeep Scan:")
            print(
                json.dumps(
                    {
                        "final_risk": deep_result.get("final_risk"),
                        "final_trust_index": deep_result.get("final_trust_index"),
                        "l1l2": deep_result.get("l1l2"),
                        "sandbox": {
                            "behavioral_prob": deep_result.get("sandbox", {}).get("behavioral_prob"),
                            "behavioral_features": deep_result.get("sandbox", {}).get("behavioral_features"),
                        },
                    },
                    indent=2,
                )
            )
        except Exception as exc:
            print(f"Sanity check failed for {url}: {exc}")


if __name__ == "__main__":
    main()
