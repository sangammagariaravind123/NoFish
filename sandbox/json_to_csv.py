import json
import os

import pandas as pd


CURRENT_DIR = os.path.dirname(__file__)
RESULTS_PATH = os.path.join(CURRENT_DIR, "results_mass.json")
DATASET_PATH = os.path.join(CURRENT_DIR, "dataset.csv")

REQUEST_TYPE_COLUMNS = [
    "script_requests",
    "stylesheet_requests",
    "image_requests",
    "font_requests",
    "xhr_fetch_requests",
    "other_requests",
]


def classify_scan_quality(item: dict) -> str:
    total_requests = int(item.get("total_requests", 0))
    document_requests = int(item.get("document_requests", 0))
    other_request_sum = sum(int(item.get(column, 0)) for column in REQUEST_TYPE_COLUMNS)

    if (
        int(item.get("error_flag", 0)) == 1
        or int(item.get("timeout_flag", 0)) == 1
        or total_requests <= 1
        or (document_requests == 1 and other_request_sum == 0)
    ):
        return "low_quality"

    if 2 <= total_requests <= 5:
        return "medium_quality"

    return "high_quality"


def main():
    with open(RESULTS_PATH, encoding="utf-8") as file:
        data = json.load(file)

    rows = []

    for item in data:
        rows.append(
            {
                "total_requests": item.get("total_requests", 0),
                "external_domain_count": item.get("external_domain_count", 0),
                "redirect_count": item.get("redirect_count", 0),
                "js_requests": item.get("js_requests", 0),
                "ip_based_requests": item.get("ip_based_requests", 0),
                "suspicious_tld_count": item.get("suspicious_tld_count", 0),
                "download_attempts": len(item.get("download_attempts", [])),
                "final_url_differs": item.get("final_url_differs", 0),
                "unique_request_domains": item.get("unique_request_domains", 0),
                "unique_request_domain_ratio": item.get("unique_request_domain_ratio", 0),
                "script_domain_count": item.get("script_domain_count", 0),
                "external_request_ratio": item.get("external_request_ratio", 0),
                "error_flag": item.get("error_flag", 0),
                "timeout_flag": item.get("timeout_flag", 0),
                "document_requests": item.get("document_requests", 0),
                "script_requests": item.get("script_requests", 0),
                "stylesheet_requests": item.get("stylesheet_requests", 0),
                "image_requests": item.get("image_requests", 0),
                "font_requests": item.get("font_requests", 0),
                "xhr_fetch_requests": item.get("xhr_fetch_requests", 0),
                "other_requests": item.get("other_requests", 0),
                "scan_quality": classify_scan_quality(item),
                "label": item.get("label", 0),
            }
        )

    df = pd.DataFrame(rows)
    df.to_csv(DATASET_PATH, index=False)

    print("dataset.csv created")
    if not df.empty:
        print("\nScan quality distribution:")
        print(df["scan_quality"].value_counts().to_string())


if __name__ == "__main__":
    main()
