import json
import pandas as pd

with open("results.json") as f:
    data = json.load(f)

df = pd.DataFrame(data)
df.to_csv("dataset.csv", index=False)

import pandas as pd
from sklearn.ensemble import RandomForestClassifier

df = pd.read_csv("dataset.csv")

X = df.drop(columns=["url", "label"])
y = df["label"]

model = RandomForestClassifier()
model.fit(X, y)

print("Model trained")