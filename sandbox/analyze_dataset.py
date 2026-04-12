import os

import pandas as pd


CURRENT_DIR = os.path.dirname(__file__)
DATASET_PATH = os.path.join(CURRENT_DIR, "dataset.csv")


def main():
    df = pd.read_csv(DATASET_PATH)
    print(f"Loaded {len(df)} rows from {DATASET_PATH}")

    if "scan_quality" in df.columns:
        print("\nScan quality counts:")
        print(df["scan_quality"].value_counts(dropna=False).to_string())

    print("\nLabel balance:")
    print(df["label"].value_counts(dropna=False).sort_index().to_string())

    print("\nAverage total_requests by label:")
    print(df.groupby("label")["total_requests"].mean().round(3).to_string())

    print("\nAverage external_request_ratio by label:")
    print(df.groupby("label")["external_request_ratio"].mean().round(3).to_string())

    warnings = []
    if "scan_quality" in df.columns:
        low_quality_ratio = (df["scan_quality"] == "low_quality").mean()
        if low_quality_ratio > 0.35:
            warnings.append(
                f"Low-quality rows are high at {low_quality_ratio:.1%}; filtering may improve model stability."
            )

    label_ratio = df["label"].mean() if len(df) else 0.0
    if label_ratio < 0.2 or label_ratio > 0.8:
        warnings.append(
            f"Class distribution is skewed (positive label ratio = {label_ratio:.1%})."
        )

    print("\nDiagnostics:")
    if warnings:
        for warning in warnings:
            print(f"- {warning}")
    else:
        print("- No major dataset skew warnings detected.")


if __name__ == "__main__":
    main()
