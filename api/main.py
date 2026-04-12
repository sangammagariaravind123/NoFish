# main.py
import asyncio
import base64
import io
import os
import re
import sys

import joblib
import matplotlib
import numpy as np
import pandas as pd
import shap
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer

from sandbox import analyze_url
from extraction import extract_features, extract_domain_parts

# from behavioral_transformer import BehavioralPredictor
from extraction import extract_all_features

domain_parts = None
matplotlib.use("Agg")
from matplotlib import pyplot as plt


API_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.dirname(API_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from behavioral_transformer import BehavioralPredictor


def project_path(*parts: str) -> str:
    return os.path.join(PROJECT_ROOT, *parts)


def resolve_minilm_source() -> tuple[str, bool]:
    snapshot_root = os.path.expanduser(
        "~/.cache/huggingface/hub/models--sentence-transformers--all-MiniLM-L6-v2/snapshots"
    )
    if os.path.isdir(snapshot_root):
        snapshots = sorted(
            (
                os.path.join(snapshot_root, name)
                for name in os.listdir(snapshot_root)
                if os.path.isdir(os.path.join(snapshot_root, name))
            ),
            key=os.path.getmtime,
            reverse=True,
        )
        for snapshot in snapshots:
            required_paths = (
                "modules.json",
                "config_sentence_transformers.json",
                "1_Pooling",
            )
            if all(
                os.path.exists(os.path.join(snapshot, rel_path))
                for rel_path in required_paths
            ):
                return snapshot, True
    return "all-MiniLM-L6-v2", False


rf_model = joblib.load(project_path("api", "rf_hybrid_minilm.pkl"))
scaler = joblib.load(project_path("api", "scaler_hybrid.pkl"))
behavioral_model = BehavioralPredictor(project_path("api", "behavior_transformer.pt"))
rf_model.n_jobs = 1
rf_tree_explainer = shap.TreeExplainer(rf_model)

minilm_source, use_local_only = resolve_minilm_source()
minilm_model = SentenceTransformer(minilm_source, local_files_only=use_local_only)

SUSPICIOUS_TLDS = [
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "xyz",
    "top",
    "club",
    "work",
    "zip",
    "link",
    "cn",
    "nz",
]
PHISHING_KEYWORDS = [
    "kyc",
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "bank",
    "payment",
    "signin",
    "confirm",
]
URL_SHORTENERS = [
    "bit.ly",
    "tinyurl",
    "goo.gl",
    "t.co",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "shorturl",
]


def compute_rule_score(url: str):
    score = 0
    rules = []
    ext = extract_domain_parts(url)
    normalized_url = url.lower()

    if ext.suffix in SUSPICIOUS_TLDS:
        score += 1
        rules.append("Suspicious_TLD")
    if "@" in url:
        score += 1
        rules.append("@_symbol")
    if url.count(".") > 4:
        score += 1
        rules.append("Excess_subdomains")
    if any(keyword in normalized_url for keyword in PHISHING_KEYWORDS):
        score += 1
        rules.append("Keyword_match")
    if any(shortener in normalized_url for shortener in URL_SHORTENERS):
        score += 1
        rules.append("Shortener")
    if re.search(r"\d", ext.domain or ""):
        score += 1
        rules.append("digits_in_domain")

    return score / 6, rules


def build_hybrid_features(url: str) -> tuple[np.ndarray, dict]:
    emb = minilm_model.encode([url], show_progress_bar=False)
    feature_map, _domain_parts = extract_features(url)
    feat = np.array(list(feature_map.values()), dtype=np.float32).reshape(1, -1)

    numeric_feature_count = int(getattr(scaler, "n_features_in_", len(scaler.mean_)))
    if feat.shape[1] > numeric_feature_count:
        feat = feat[:, :numeric_feature_count]

    pad = np.zeros((1, max(0, numeric_feature_count - feat.shape[1])), dtype=np.float32)
    numeric_features = np.hstack([feat, pad])
    if numeric_features.shape[1] > numeric_feature_count:
        numeric_features = numeric_features[:, :numeric_feature_count]

    num_scaled = scaler.transform(numeric_features)
    return np.hstack([emb, num_scaled]), feature_map


def predict_url(url: str):
    X_hybrid, _feature_map = build_hybrid_features(url)
    prob = rf_model.predict_proba(X_hybrid)[0][1]
    rule_score, rules = compute_rule_score(url)

    trust_index = 0.7 * prob + 0.3 * (1 - rule_score)
    trust_index = max(0.0, min(1.0, trust_index))

    if trust_index >= 0.6:
        risk = "Safe"
    elif trust_index >= 0.4:
        risk = "Suspicious"
    else:
        risk = "Phishing"

    return {
        "trust_index": trust_index,
        "risk": risk,
        "ml_prob": prob,
        "rule_score": rule_score,
        "triggered_rules": rules,
    }


def unwrap_positive_class_shap(shap_values) -> np.ndarray:
    if isinstance(shap_values, list):
        return np.array(shap_values[1 if len(shap_values) > 1 else 0])[0]

    values = np.array(shap_values)
    if values.ndim == 3:
        class_index = 1 if values.shape[-1] > 1 else 0
        return values[0, :, class_index]
    if values.ndim == 2:
        return values[0]
    raise ValueError(f"Unsupported SHAP output shape: {values.shape}")


def build_shap_graph(url: str) -> dict:
    hybrid_features, feature_map = build_hybrid_features(url)
    shap_values = unwrap_positive_class_shap(
        rf_tree_explainer.shap_values(hybrid_features)
    )

    embedding_size = hybrid_features.shape[1] - len(feature_map)
    embedding_contribution = (
        float(np.sum(shap_values[:embedding_size])) if embedding_size > 0 else 0.0
    )

    labels = ["MiniLM semantic signal", *feature_map.keys()]
    contributions = np.array(
        [
            embedding_contribution,
            *shap_values[embedding_size : embedding_size + len(feature_map)],
        ],
        dtype=np.float64,
    )
    feature_values = [None, *feature_map.values()]

    top_indices = np.argsort(np.abs(contributions))[-12:]
    ordered = top_indices[np.argsort(np.abs(contributions[top_indices]))]

    plot_labels = [labels[index] for index in ordered]
    plot_values = contributions[ordered]
    colors = ["#f97316" if value > 0 else "#2563eb" for value in plot_values]

    fig, ax = plt.subplots(figsize=(10, 5.6))
    ax.barh(range(len(plot_values)), plot_values, color=colors, alpha=0.9)
    ax.set_yticks(range(len(plot_values)))
    ax.set_yticklabels(plot_labels, fontsize=9)
    ax.axvline(0, color="#94a3b8", linewidth=1)
    ax.set_xlabel("SHAP value impact on phishing score")
    ax.set_title("Top feature contributions for this URL")
    ax.grid(axis="x", linestyle="--", alpha=0.25)
    fig.tight_layout()

    buffer = io.BytesIO()
    fig.savefig(buffer, format="png", dpi=180, bbox_inches="tight")
    plt.close(fig)
    image_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

    explanation_items = []
    for index in ordered[::-1]:
        explanation_items.append(
            {
                "feature": labels[index],
                "shap_value": float(contributions[index]),
                "feature_value": None if index == 0 else feature_values[index],
            }
        )

    return {
        "url": url,
        "graph_data_uri": f"data:image/png;base64,{image_base64}",
        "top_features": explanation_items,
    }


app = FastAPI(
    title="PhishGuard API", description="URL phishing detection", version="1.0"
)


class URLRequest(BaseModel):
    url: str


@app.post("/predict")
async def predict(request: URLRequest):
    try:
        return predict_url(request.url)
    except Exception as e:
        import traceback

        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/deep_scan")
async def deep_scan(request: URLRequest):
    try:
        l1l2_result = predict_url(request.url)
        sandbox_result = await asyncio.to_thread(analyze_url, request.url)

        behavioral_features = {
            "total_requests": sandbox_result.get("total_requests", 0),
            "external_domain_count": sandbox_result.get("external_domain_count", 0),
            "redirect_count": sandbox_result.get("redirect_count", 0),
            "js_requests": sandbox_result.get("js_requests", 0),
            "ip_based_requests": sandbox_result.get("ip_based_requests", 0),
            "suspicious_tld_count": sandbox_result.get("suspicious_tld_count", 0),
            "download_attempts": len(sandbox_result.get("download_attempts", [])),
            "final_url_differs": sandbox_result.get("final_url_differs", 0),
            "unique_request_domains": sandbox_result.get("unique_request_domains", 0),
            "unique_request_domain_ratio": sandbox_result.get(
                "unique_request_domain_ratio", 0
            ),
            "script_domain_count": sandbox_result.get("script_domain_count", 0),
            "external_request_ratio": sandbox_result.get("external_request_ratio", 0),
            "error_flag": sandbox_result.get("error_flag", 0),
            "timeout_flag": sandbox_result.get("timeout_flag", 0),
            "document_requests": sandbox_result.get("document_requests", 0),
            "script_requests": sandbox_result.get("script_requests", 0),
            "stylesheet_requests": sandbox_result.get("stylesheet_requests", 0),
            "image_requests": sandbox_result.get("image_requests", 0),
            "font_requests": sandbox_result.get("font_requests", 0),
            "xhr_fetch_requests": sandbox_result.get("xhr_fetch_requests", 0),
            "other_requests": sandbox_result.get("other_requests", 0),
        }

        behavioral_prob = float(behavioral_model.predict_proba(behavioral_features)[0])

        if behavioral_prob > 0.6:
            final_risk = "Phishing"
        elif behavioral_prob > 0.4:
            final_risk = "Suspicious"
        else:
            final_risk = "Safe"

        final_trust = 1 - behavioral_prob
        explanation = "Sandbox executed the URL in an isolated browser and extracted runtime behavior."

        return {
            "scanned_url": request.url,
            "final_risk": final_risk,
            "final_trust_index": final_trust,
            "l1l2": l1l2_result,
            "sandbox": {
                "behavioral_prob": behavioral_prob,
                "behavioral_features": behavioral_features,
                "raw_output": sandbox_result,
                "model_type": "transformer",
            },
            "explanation": explanation,
        }

    except Exception as e:
        import traceback

        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/explain_shap")
async def explain_shap(request: URLRequest):
    try:
        return build_shap_graph(request.url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/")
async def root():
    return {
        "message": "PhishGuard API is running. Use POST /predict with JSON { 'url': '...' }"
    }
