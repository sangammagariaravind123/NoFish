import pandas as pd
import json

from sandbox import analyze_url

df = pd.read_csv("data/urls_labeled.csv")

# ⚠️ TEST FIRST
df = df.head(20)

results = []

for i, row in df.iterrows():
    url = row["url"]
    label = row["label"]

    print(f"[{i}] Scanning: {url}")

    try:
        r = analyze_url(url)
        r["label"] = label
        results.append(r)

    except Exception as e:
        print("Error:", e)

with open("results_mass.json", "w") as f:
    json.dump(results, f, indent=2)

print("Done → results.json")