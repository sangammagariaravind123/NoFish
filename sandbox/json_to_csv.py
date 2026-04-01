import json
import pandas as pd

with open("results_mass.json") as f:
    data = json.load(f)

rows = []

for item in data:
    rows.append({
        # old
        "total_requests": item.get("total_requests", 0),
        "external_domain_count": item.get("external_domain_count", 0),
        "redirect_count": item.get("redirect_count", 0),
        "js_requests": item.get("js_requests", 0),
        "ip_based_requests": item.get("ip_based_requests", 0),
        "suspicious_tld_count": item.get("suspicious_tld_count", 0),
        "download_attempts": len(item.get("download_attempts", [])),

        # new
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

        "label": item.get("label", 0)
    })

df = pd.DataFrame(rows)
df.to_csv("dataset.csv", index=False)

print("dataset.csv created")