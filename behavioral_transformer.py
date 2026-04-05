import os
from dataclasses import dataclass

import numpy as np
import pandas as pd
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset


FEATURE_COLUMNS = [
    "total_requests",
    "external_domain_count",
    "redirect_count",
    "js_requests",
    "ip_based_requests",
    "suspicious_tld_count",
    "download_attempts",
    "final_url_differs",
    "unique_request_domains",
    "unique_request_domain_ratio",
    "script_domain_count",
    "external_request_ratio",
    "error_flag",
    "timeout_flag",
    "document_requests",
    "script_requests",
    "stylesheet_requests",
    "image_requests",
    "font_requests",
    "xhr_fetch_requests",
    "other_requests",
]

COUNT_FEATURE_COLUMNS = [
    "total_requests",
    "external_domain_count",
    "redirect_count",
    "js_requests",
    "ip_based_requests",
    "suspicious_tld_count",
    "download_attempts",
    "unique_request_domains",
    "script_domain_count",
    "document_requests",
    "script_requests",
    "stylesheet_requests",
    "image_requests",
    "font_requests",
    "xhr_fetch_requests",
    "other_requests",
]


@dataclass
class BehavioralTransformerConfig:
    d_model: int = 64
    nhead: int = 4
    num_layers: int = 2
    dim_feedforward: int = 128
    dense_hidden: int = 64
    dense_out: int = 32
    dropout: float = 0.1


class BehavioralTransformer(nn.Module):
    def __init__(self, num_features: int, config: BehavioralTransformerConfig):
        super().__init__()
        self.num_features = num_features
        self.value_projection = nn.Sequential(
            nn.Linear(1, config.d_model),
            nn.GELU(),
            nn.LayerNorm(config.d_model),
        )
        self.feature_embedding = nn.Embedding(num_features + 1, config.d_model)
        self.cls_token = nn.Parameter(torch.zeros(1, 1, config.d_model))

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=config.d_model,
            nhead=config.nhead,
            dim_feedforward=config.dim_feedforward,
            dropout=config.dropout,
            batch_first=True,
            activation="gelu",
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=config.num_layers)
        self.cls_norm = nn.LayerNorm(config.d_model)

        self.dense_branch = nn.Sequential(
            nn.Linear(num_features, config.dense_hidden),
            nn.GELU(),
            nn.Dropout(config.dropout),
            nn.Linear(config.dense_hidden, config.dense_out),
            nn.GELU(),
        )

        fused_dim = config.d_model + config.dense_out
        self.fusion_norm = nn.LayerNorm(fused_dim)
        self.classifier = nn.Sequential(
            nn.Linear(fused_dim, 32),
            nn.GELU(),
            nn.Dropout(config.dropout),
            nn.Linear(32, 1),
        )

        feature_ids = torch.arange(1, num_features + 1, dtype=torch.long)
        self.register_buffer("feature_ids", feature_ids, persistent=False)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        tokens = self.value_projection(x.unsqueeze(-1))
        tokens = tokens + self.feature_embedding(self.feature_ids).unsqueeze(0)

        cls_token = self.cls_token.expand(x.size(0), -1, -1)
        cls_token = cls_token + self.feature_embedding.weight[0].view(1, 1, -1)

        encoded = self.encoder(torch.cat([cls_token, tokens], dim=1))
        cls_out = self.cls_norm(encoded[:, 0, :])
        dense_out = self.dense_branch(x)
        fused = self.fusion_norm(torch.cat([cls_out, dense_out], dim=1))

        return self.classifier(fused).squeeze(-1)


class BehavioralPredictor:
    def __init__(self, artifact_path: str, device: str | None = None):
        map_location = device or ("cuda" if torch.cuda.is_available() else "cpu")
        artifact = torch.load(artifact_path, map_location=map_location)

        self.feature_columns = artifact["feature_columns"]
        self.preprocessing = artifact.get(
            "preprocessing",
            {"log1p_columns": COUNT_FEATURE_COLUMNS},
        )

        config = BehavioralTransformerConfig(**artifact["config"])
        self.model = BehavioralTransformer(len(self.feature_columns), config)
        self.model.load_state_dict(artifact["state_dict"])
        self.model.eval()
        self.device = torch.device(map_location)
        self.model.to(self.device)

        self.feature_mean = np.array(artifact["feature_mean"], dtype=np.float32)
        self.feature_std = np.array(artifact["feature_std"], dtype=np.float32)
        self.metadata = artifact.get("metadata", {})

    def _prepare_frame(self, features: pd.DataFrame | dict) -> pd.DataFrame:
        if isinstance(features, dict):
            frame = pd.DataFrame([features])
        else:
            frame = features.copy()

        for column in self.feature_columns:
            if column not in frame:
                frame[column] = 0.0

        return frame[self.feature_columns].copy()

    def _apply_preprocessing(self, frame: pd.DataFrame) -> pd.DataFrame:
        transformed = frame.copy()
        for column in self.preprocessing.get("log1p_columns", []):
            if column in transformed.columns:
                transformed[column] = np.log1p(transformed[column].clip(lower=0))
        return transformed

    def _prepare_array(self, features: pd.DataFrame | dict) -> np.ndarray:
        frame = self._prepare_frame(features)
        frame = self._apply_preprocessing(frame)
        values = frame.astype("float32").to_numpy()
        return (values - self.feature_mean) / self.feature_std

    def predict_proba(self, features: pd.DataFrame | dict) -> np.ndarray:
        values = self._prepare_array(features)
        inputs = torch.tensor(values, dtype=torch.float32, device=self.device)

        with torch.no_grad():
            logits = self.model(inputs)
            probabilities = torch.sigmoid(logits).cpu().numpy()

        return probabilities


def preprocess_behavioral_features(features: pd.DataFrame) -> pd.DataFrame:
    transformed = features.copy()
    for column in COUNT_FEATURE_COLUMNS:
        if column in transformed.columns:
            transformed[column] = np.log1p(transformed[column].clip(lower=0))
    return transformed


def load_behavioral_dataset(csv_path: str) -> tuple[pd.DataFrame, pd.Series]:
    df = pd.read_csv(csv_path)

    missing = [column for column in FEATURE_COLUMNS if column not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing required feature columns: {missing}")

    if "label" not in df.columns:
        raise ValueError("Dataset must contain a 'label' column.")

    features = df[FEATURE_COLUMNS].astype("float32")
    features = preprocess_behavioral_features(features)
    labels = df["label"].astype("int64")
    return features, labels


def build_dataloader(features: np.ndarray, labels: np.ndarray, batch_size: int, shuffle: bool) -> DataLoader:
    dataset = TensorDataset(
        torch.tensor(features, dtype=torch.float32),
        torch.tensor(labels, dtype=torch.float32),
    )
    return DataLoader(dataset, batch_size=batch_size, shuffle=shuffle)


def save_behavioral_artifact(
    output_path: str,
    model: BehavioralTransformer,
    config: BehavioralTransformerConfig,
    feature_mean: np.ndarray,
    feature_std: np.ndarray,
    metadata: dict,
) -> None:
    artifact = {
        "state_dict": model.state_dict(),
        "config": {
            "d_model": config.d_model,
            "nhead": config.nhead,
            "num_layers": config.num_layers,
            "dim_feedforward": config.dim_feedforward,
            "dense_hidden": config.dense_hidden,
            "dense_out": config.dense_out,
            "dropout": config.dropout,
        },
        "feature_columns": FEATURE_COLUMNS,
        "feature_mean": feature_mean.astype(np.float32).tolist(),
        "feature_std": feature_std.astype(np.float32).tolist(),
        "preprocessing": {
            "log1p_columns": COUNT_FEATURE_COLUMNS,
        },
        "metadata": metadata,
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    torch.save(artifact, output_path)
