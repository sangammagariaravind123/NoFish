import pandas as pd
import json
from sandbox import analyze_url
from tqdm import tqdm
df = pd.read_csv("urls_labeled.csv")

# test first
df = df.head(4000)

results = []
total = len(df)

for i, row in tqdm(df.iterrows(), total=total):
    url = row["url"]
    label = row["label"]

    try:
        r = analyze_url(url)
        r["label"] = label
        results.append(r)

    except Exception as e:
        print("Error:", e)

with open("results_mass.json", "w") as f:
    json.dump(results, f, indent=2)

print("\nDone → results_mass.json")