import os
import sys

<<<<<<< HEAD
import numpy as np
import torch
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score
=======
import joblib
import numpy as np
import pandas as pd
import torch
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
>>>>>>> 452c45a0dbcd912ee93bdb2a0b606502a899242d
from sklearn.model_selection import train_test_split
from torch import nn

CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from behavioral_transformer import (
<<<<<<< HEAD
    BehavioralTransformer,
    BehavioralTransformerConfig,
    build_dataloader,
    load_behavioral_dataset,
=======
    FEATURE_COLUMNS,
    BehavioralTransformer,
    BehavioralTransformerConfig,
    build_dataloader,
    preprocess_behavioral_features,
>>>>>>> 452c45a0dbcd912ee93bdb2a0b606502a899242d
    save_behavioral_artifact,
)


DATASET_PATH = os.path.join(CURRENT_DIR, "dataset.csv")
ARTIFACT_PATHS = [
    os.path.join(CURRENT_DIR, "behavior_transformer.pt"),
    os.path.join(PROJECT_ROOT, "api", "behavior_transformer.pt"),
]
<<<<<<< HEAD
=======
RF_ARTIFACT_PATH = os.path.join(CURRENT_DIR, "model_rf.pkl")
>>>>>>> 452c45a0dbcd912ee93bdb2a0b606502a899242d

EPOCHS = 30
BATCH_SIZE = 64
LEARNING_RATE = 8e-4
WEIGHT_DECAY = 5e-4
RANDOM_STATE = 42
<<<<<<< HEAD
=======
USE_LOW_QUALITY = False
>>>>>>> 452c45a0dbcd912ee93bdb2a0b606502a899242d


def standardize(
    train_array: np.ndarray,
    eval_array: np.ndarray,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    mean = train_array.mean(axis=0)
    std = train_array.std(axis=0)
    std[std < 1e-6] = 1.0
    return (train_array - mean) / std, (eval_array - mean) / std, mean, std


<<<<<<< HEAD
=======
def evaluate_binary(y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.5) -> dict:
    y_pred = (y_prob >= threshold).astype(int)
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "roc_auc": roc_auc_score(y_true, y_prob),
        "report": classification_report(y_true, y_pred, digits=4),
        "y_pred": y_pred,
    }


def print_metric_block(title: str, metrics: dict) -> None:
    print(f"\n{title}")
    print(f"  Accuracy : {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall   : {metrics['recall']:.4f}")
    print(f"  F1       : {metrics['f1']:.4f}")
    print(f"  ROC-AUC  : {metrics['roc_auc']:.4f}")


def load_training_frame(dataset_path: str, use_low_quality: bool) -> pd.DataFrame:
    df = pd.read_csv(dataset_path)
    if "scan_quality" not in df.columns:
        df["scan_quality"] = "unknown"

    print(f"Total rows in dataset.csv: {len(df)}")
    print("\nRows by scan_quality:")
    print(df["scan_quality"].value_counts(dropna=False).to_string())

    if not use_low_quality and "scan_quality" in df.columns:
        df = df[df["scan_quality"] != "low_quality"].copy()

    print(f"\nUSE_LOW_QUALITY = {use_low_quality}")
    print(f"Rows after filtering: {len(df)}")
    print("Class balance after filtering:")
    print(df["label"].value_counts(dropna=False).sort_index().to_string())

    missing = [column for column in FEATURE_COLUMNS if column not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing required feature columns: {missing}")

    return df


>>>>>>> 452c45a0dbcd912ee93bdb2a0b606502a899242d
def train_epoch(model, dataloader, loss_fn, optimizer, device):
    model.train()
    total_loss = 0.0

    for batch_features, batch_labels in dataloader:
        batch_features = batch_features.to(device)
        batch_labels = batch_labels.to(device)

        optimizer.zero_grad(set_to_none=True)
        logits = model(batch_features)
        loss = loss_fn(logits, batch_labels)
        loss.backward()
        optimizer.step()

        total_loss += loss.item() * batch_features.size(0)

    return total_loss / len(dataloader.dataset)


<<<<<<< HEAD
def evaluate(model, dataloader, device):
=======
def evaluate_transformer(model, dataloader, device):
>>>>>>> 452c45a0dbcd912ee93bdb2a0b606502a899242d
    model.eval()
    probabilities = []
    labels = []

    with torch.no_grad():
        for batch_features, batch_labels in dataloader:
            batch_features = batch_features.to(device)
            logits = model(batch_features)
            probs = torch.sigmoid(logits).cpu().numpy()
            probabilities.append(probs)
            labels.append(batch_labels.numpy())

    y_prob = np.concatenate(probabilities)
    y_true = np.concatenate(labels).astype(int)
<<<<<<< HEAD
    y_pred = (y_prob >= 0.5).astype(int)

    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "roc_auc": roc_auc_score(y_true, y_prob),
        "report": classification_report(y_true, y_pred, digits=4),
        "y_prob": y_prob,
        "y_true": y_true,
    }


def main():
    features, labels = load_behavioral_dataset(DATASET_PATH)
=======
    metrics = evaluate_binary(y_true, y_prob)
    metrics["y_prob"] = y_prob
    metrics["y_true"] = y_true
    return metrics


def main():
    df = load_training_frame(DATASET_PATH, USE_LOW_QUALITY)
    features = preprocess_behavioral_features(df[FEATURE_COLUMNS].astype("float32"))
    labels = df["label"].astype("int64")

>>>>>>> 452c45a0dbcd912ee93bdb2a0b606502a899242d
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        features.to_numpy(),
        labels.to_numpy(),
        test_size=0.2,
        random_state=RANDOM_STATE,
        stratify=labels.to_numpy(),
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val,
        y_train_val,
        test_size=0.2,
        random_state=RANDOM_STATE,
        stratify=y_train_val,
    )

    X_train_scaled, X_val_scaled, mean, std = standardize(X_train, X_val)
    X_test_scaled = (X_test - mean) / std

    train_loader = build_dataloader(X_train_scaled, y_train, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = build_dataloader(X_val_scaled, y_val, batch_size=BATCH_SIZE, shuffle=False)
    test_loader = build_dataloader(X_test_scaled, y_test, batch_size=BATCH_SIZE, shuffle=False)

    config = BehavioralTransformerConfig()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = BehavioralTransformer(num_features=X_train.shape[1], config=config).to(device)

    positive_count = max(float(y_train.sum()), 1.0)
    negative_count = max(float(len(y_train) - y_train.sum()), 1.0)
    pos_weight = torch.tensor([negative_count / positive_count], dtype=torch.float32, device=device)

    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optimizer = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)

    best_state = None
    best_val_auc = -1.0

<<<<<<< HEAD
    print(f"Training behavioral Transformer on {len(features)} samples")
=======
    print(f"\nTraining behavioral Transformer on {len(features)} samples")
>>>>>>> 452c45a0dbcd912ee93bdb2a0b606502a899242d
    print(
        f"Train size: {len(X_train)} | Val size: {len(X_val)} | "
        f"Test size: {len(X_test)} | Device: {device}"
    )

    for epoch in range(1, EPOCHS + 1):
        train_loss = train_epoch(model, train_loader, loss_fn, optimizer, device)
<<<<<<< HEAD
        val_metrics = evaluate(model, val_loader, device)
=======
        val_metrics = evaluate_transformer(model, val_loader, device)
>>>>>>> 452c45a0dbcd912ee93bdb2a0b606502a899242d

        if val_metrics["roc_auc"] > best_val_auc:
            best_val_auc = val_metrics["roc_auc"]
            best_state = {key: value.detach().cpu().clone() for key, value in model.state_dict().items()}

        print(
            f"Epoch {epoch:02d}/{EPOCHS} | "
            f"train_loss={train_loss:.4f} | "
            f"val_acc={val_metrics['accuracy']:.4f} | "
            f"val_auc={val_metrics['roc_auc']:.4f}"
        )

    if best_state is not None:
        model.load_state_dict(best_state)

<<<<<<< HEAD
    final_metrics = evaluate(model, test_loader, device)
    print("\nFinal test accuracy:", round(final_metrics["accuracy"], 4))
    print("Final test ROC-AUC:", round(final_metrics["roc_auc"], 4))
    print("\nClassification report:\n")
    print(final_metrics["report"])
=======
    transformer_metrics = evaluate_transformer(model, test_loader, device)
    print_metric_block("Transformer Test Metrics", transformer_metrics)
    print("\nTransformer classification report:\n")
    print(transformer_metrics["report"])
>>>>>>> 452c45a0dbcd912ee93bdb2a0b606502a899242d

    metadata = {
        "train_size": int(len(X_train)),
        "val_size": int(len(X_val)),
        "test_size": int(len(X_test)),
<<<<<<< HEAD
        "accuracy": float(final_metrics["accuracy"]),
        "roc_auc": float(final_metrics["roc_auc"]),
        "epochs": EPOCHS,
        "notes": "log1p count preprocessing + CLS transformer encoder + dense residual branch",
=======
        "accuracy": float(transformer_metrics["accuracy"]),
        "precision": float(transformer_metrics["precision"]),
        "recall": float(transformer_metrics["recall"]),
        "f1": float(transformer_metrics["f1"]),
        "roc_auc": float(transformer_metrics["roc_auc"]),
        "epochs": EPOCHS,
        "use_low_quality": USE_LOW_QUALITY,
        "notes": "quality-aware dataset filtering + RF baseline comparison",
>>>>>>> 452c45a0dbcd912ee93bdb2a0b606502a899242d
    }

    model = model.cpu()
    for artifact_path in ARTIFACT_PATHS:
        save_behavioral_artifact(
            output_path=artifact_path,
            model=model,
            config=config,
            feature_mean=mean,
            feature_std=std,
            metadata=metadata,
        )
        print(f"Saved Transformer artifact -> {artifact_path}")

<<<<<<< HEAD
=======
    rf_model = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    rf_model.fit(X_train_scaled, y_train)
    rf_prob = rf_model.predict_proba(X_test_scaled)[:, 1]
    rf_metrics = evaluate_binary(y_test.astype(int), rf_prob)
    print_metric_block("Random Forest Baseline Metrics", rf_metrics)
    print("\nRandom Forest classification report:\n")
    print(rf_metrics["report"])

    joblib.dump(
        {
            "model": rf_model,
            "feature_columns": FEATURE_COLUMNS,
            "feature_mean": mean,
            "feature_std": std,
            "metadata": {
                "use_low_quality": USE_LOW_QUALITY,
                "accuracy": float(rf_metrics["accuracy"]),
                "precision": float(rf_metrics["precision"]),
                "recall": float(rf_metrics["recall"]),
                "f1": float(rf_metrics["f1"]),
                "roc_auc": float(rf_metrics["roc_auc"]),
            },
        },
        RF_ARTIFACT_PATH,
    )
    print(f"Saved RF baseline artifact -> {RF_ARTIFACT_PATH}")

>>>>>>> 452c45a0dbcd912ee93bdb2a0b606502a899242d

if __name__ == "__main__":
    main()
