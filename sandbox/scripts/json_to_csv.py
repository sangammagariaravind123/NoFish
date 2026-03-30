import json
import pandas as pd

with open("../results.json") as f:
    data = json.load(f)

rows = []

for item in data:
    rows.append({
        "total_requests": item.get("total_requests", 0),
        "external_domain_count": item.get("external_domain_count", 0),
        "redirect_count": item.get("redirect_count", 0),
        "js_requests": item.get("js_requests", 0),
        "ip_based_requests": item.get("ip_based_requests", 0),
        "suspicious_tld_count": item.get("suspicious_tld_count", 0),
        "download_attempts": len(item.get("download_attempts", [])),
        "label": item.get("label", 0)
    })

df = pd.DataFrame(rows)
df.to_csv("dataset.csv", index=False)

print("dataset.csv created")