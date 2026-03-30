import pandas as pd

df = pd.read_csv("dataset_phishing.csv")

print(df.columns)

# keep only needed columns
df = df[["url", "status"]]

# clean
df = df.dropna()
df = df[df["url"].str.startswith("http")]

# 🔥 convert text labels → numeric
df["label"] = df["status"].apply(lambda x: 1 if x.strip().lower() == "phishing" else 0)

# keep only needed columns
df = df[["url", "label"]]

df.to_csv("../data/urls_labeled.csv", index=False)

print("urls_labeled.csv created")