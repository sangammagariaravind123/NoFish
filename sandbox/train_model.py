import os
import sys

import numpy as np
import torch
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from torch import nn

CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from behavioral_transformer import (
    BehavioralTransformer,
    BehavioralTransformerConfig,
    build_dataloader,
    load_behavioral_dataset,
    save_behavioral_artifact,
)


DATASET_PATH = os.path.join(CURRENT_DIR, "dataset.csv")
ARTIFACT_PATHS = [
    os.path.join(CURRENT_DIR, "behavior_transformer.pt"),
    os.path.join(PROJECT_ROOT, "api", "behavior_transformer.pt"),
]

EPOCHS = 30
BATCH_SIZE = 64
LEARNING_RATE = 8e-4
WEIGHT_DECAY = 5e-4
RANDOM_STATE = 42


def standardize(
    train_array: np.ndarray,
    eval_array: np.ndarray,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    mean = train_array.mean(axis=0)
    std = train_array.std(axis=0)
    std[std < 1e-6] = 1.0
    return (train_array - mean) / std, (eval_array - mean) / std, mean, std


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


def evaluate(model, dataloader, device):
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

    print(f"Training behavioral Transformer on {len(features)} samples")
    print(
        f"Train size: {len(X_train)} | Val size: {len(X_val)} | "
        f"Test size: {len(X_test)} | Device: {device}"
    )

    for epoch in range(1, EPOCHS + 1):
        train_loss = train_epoch(model, train_loader, loss_fn, optimizer, device)
        val_metrics = evaluate(model, val_loader, device)

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

    final_metrics = evaluate(model, test_loader, device)
    print("\nFinal test accuracy:", round(final_metrics["accuracy"], 4))
    print("Final test ROC-AUC:", round(final_metrics["roc_auc"], 4))
    print("\nClassification report:\n")
    print(final_metrics["report"])

    metadata = {
        "train_size": int(len(X_train)),
        "val_size": int(len(X_val)),
        "test_size": int(len(X_test)),
        "accuracy": float(final_metrics["accuracy"]),
        "roc_auc": float(final_metrics["roc_auc"]),
        "epochs": EPOCHS,
        "notes": "log1p count preprocessing + CLS transformer encoder + dense residual branch",
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


if __name__ == "__main__":
    main()
