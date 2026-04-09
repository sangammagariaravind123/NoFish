# main.py
import asyncio
import os
import sys

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer

from sandbox import analyze_url
from extract_features import extract_basic_features, extract_domain_parts

# from behavioral_transformer import BehavioralPredictor
from extract_features import extract_all_features


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


# --- Load the trained models ---
rf_model = joblib.load(project_path("api", "rf_hybrid_minilm.pkl"))
scaler = joblib.load(project_path("api", "scaler_hybrid.pkl"))
behavioral_model = BehavioralPredictor(project_path("api", "behavior_transformer.pt"))
rf_model.n_jobs = 1

# --- Load the MiniLM model ---
minilm_source, use_local_only = resolve_minilm_source()
minilm_model = SentenceTransformer(minilm_source, local_files_only=use_local_only)

# --- Rule engine (same as in your app) ---
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
]
PHISHING_KEYWORDS = [
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


def compute_rule_score(url):
    score = 0
    rules = []
    ext = extract_domain_parts(url)
    if ext.suffix in SUSPICIOUS_TLDS:
        score += 1
        rules.append("Suspicious_TLD")
    if "@" in url:
        score += 1
        rules.append("@_symbol")
    if url.count(".") > 4:
        score += 1
        rules.append("Excess_subdomains")
    if any(k in url.lower() for k in PHISHING_KEYWORDS):
        score += 1
        rules.append("Keyword_match")
    if any(short in url.lower() for short in URL_SHORTENERS):
        score += 1
        rules.append("Shortener")
    return score / 5, rules


def predict_url(url):
    emb = minilm_model.encode([url], show_progress_bar=False)
<<<<<<< HEAD
    feat = np.array(
        list(extract_basic_features(url).values()), dtype=np.float32
    ).reshape(1, -1)
=======
    feat = np.array(list(extract_features(url).values()), dtype=np.float32).reshape(
        1, -1
    )
>>>>>>> 0e4c43e (v6.4.3 added dataset file)
    numeric_feature_count = int(getattr(scaler, "n_features_in_", len(scaler.mean_)))
    if feat.shape[1] > numeric_feature_count:
        feat = feat[:, :numeric_feature_count]

    pad = np.zeros((1, max(0, numeric_feature_count - feat.shape[1])), dtype=np.float32)
    numeric_features = np.hstack([feat, pad])
    if numeric_features.shape[1] > numeric_feature_count:
        numeric_features = numeric_features[:, :numeric_feature_count]

    num_scaled = scaler.transform(numeric_features)
    X_hybrid = np.hstack([emb, num_scaled])

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


@app.get("/")
async def root():
    return {
        "message": "PhishGuard API is running. Use POST /predict with JSON { 'url': '...' }"
    }
