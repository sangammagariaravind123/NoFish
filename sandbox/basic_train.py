import json
import os

import pandas as pd

from train_model import main as train_transformer


CURRENT_DIR = os.path.dirname(__file__)
RESULTS_PATH = os.path.join(CURRENT_DIR, "results.json")
DATASET_PATH = os.path.join(CURRENT_DIR, "dataset.csv")


def main():
    with open(RESULTS_PATH, encoding="utf-8") as f:
        data = json.load(f)

    df = pd.DataFrame(data)
    df.to_csv(DATASET_PATH, index=False)
    print(f"Converted {RESULTS_PATH} -> {DATASET_PATH}")

    print("Starting Transformer-based sandbox training...")
    train_transformer()


if __name__ == "__main__":
    main()
