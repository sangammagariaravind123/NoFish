import os
import sys

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, precision_score, recall_score

CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from behavioral_transformer import BehavioralPredictor, FEATURE_COLUMNS


DATASET_PATH = os.path.join(CURRENT_DIR, "dataset.csv")
ARTIFACT_PATH = os.path.join(CURRENT_DIR, "behavior_transformer.pt")


def evaluate_threshold(y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> dict:
    y_pred = (y_prob >= threshold).astype(int)
    false_positive_rate = ((y_pred == 1) & (y_true == 0)).sum() / max((y_true == 0).sum(), 1)
    return {
        "threshold": threshold,
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "fpr": false_positive_rate,
    }


def main():
    df = pd.read_csv(DATASET_PATH)
    predictor = BehavioralPredictor(ARTIFACT_PATH)

    features = df[FEATURE_COLUMNS]
    y_true = df["label"].astype(int).to_numpy()
    y_prob = predictor.predict_proba(features)

    thresholds = np.round(np.arange(0.20, 0.91, 0.01), 2)
    scored = [evaluate_threshold(y_true, y_prob, threshold) for threshold in thresholds]

    phishing_choice = max(
        scored,
        key=lambda item: (item["f1"], item["precision"], -item["fpr"]),
    )

    suspicious_candidates = [item for item in scored if item["threshold"] < phishing_choice["threshold"]]
    suspicious_choice = max(
        suspicious_candidates,
        key=lambda item: (item["recall"] - (0.35 * item["fpr"]), item["precision"]),
    )

    print("Recommended thresholds")
    print(f"  suspicious >= {suspicious_choice['threshold']:.2f}")
    print(f"  phishing   >= {phishing_choice['threshold']:.2f}")

    print("\nPhishing threshold metrics:")
    print(
        f"  precision={phishing_choice['precision']:.4f} "
        f"recall={phishing_choice['recall']:.4f} "
        f"f1={phishing_choice['f1']:.4f} "
        f"fpr={phishing_choice['fpr']:.4f}"
    )

    print("\nSuspicious threshold metrics:")
    print(
        f"  precision={suspicious_choice['precision']:.4f} "
        f"recall={suspicious_choice['recall']:.4f} "
        f"f1={suspicious_choice['f1']:.4f} "
        f"fpr={suspicious_choice['fpr']:.4f}"
    )


if __name__ == "__main__":
    main()
