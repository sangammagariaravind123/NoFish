# main.py
import asyncio
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import pandas as pd
from sandbox import analyze_url
import numpy as np
import tldextract
import re
from sentence_transformers import SentenceTransformer
import os

# --- Load the trained model and scaler ---
# Assume these files are in the same directory as this script.
# If they are elsewhere, adjust the paths.
rf_model = joblib.load("rf_hybrid_minilm.pkl")
scaler = joblib.load("scaler_hybrid.pkl")

behavioral_model = joblib.load("model.pkl")

# --- Load the MiniLM model ---
# This will download the model if not cached; first run may take a moment.
minilm_model = SentenceTransformer("all-MiniLM-L6-v2")

# --- Rule engine (same as in your app) ---
SUSPICIOUS_TLDS = ["tk","ml","ga","cf","gq","xyz","top","club","work","zip","link","cn"]
PHISHING_KEYWORDS = ["login","verify","update","secure","account","bank","payment","signin","confirm"]
URL_SHORTENERS = ["bit.ly","tinyurl","goo.gl","t.co","is.gd","buff.ly","adf.ly","shorturl"]

def compute_rule_score(url):
    score = 0
    rules = []
    ext = tldextract.extract(url)
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

# --- Basic numeric feature extractor (same as app) ---
def extract_basic_features(url):
    u = str(url)
    return {
        "length_url": len(u),
        "nb_dots": u.count("."),
        "nb_hyphens": u.count("-"),
        "https_token": 1 if "https" in u.lower() else 0,
        "ratio_digits_url": sum(c.isdigit() for c in u) / len(u) if len(u) > 0 else 0,
    }

# --- Prediction function ---
def predict_url(url):
    # 1. Get MiniLM embedding
    emb = minilm_model.encode([url], show_progress_bar=False)

    # 2. Get basic numeric features
    feat = np.array(list(extract_basic_features(url).values())).reshape(1, -1)

    # 3. Pad to match the number of features the scaler expects
    pad = np.zeros((1, scaler.mean_.shape[0] - feat.shape[1]))
    num_scaled = np.hstack([feat, pad])

    # 4. Combine embedding + numeric
    X_hybrid = np.hstack([emb, num_scaled])

    # 5. Get ML probability (phishing class)
    prob = rf_model.predict_proba(X_hybrid)[0][1]

    # 6. Rule score
    rule_score, rules = compute_rule_score(url)

    # 7. Compute Trust Index
    trust_index = 0.7 * prob + 0.3 * (1 - rule_score)
    trust_index = max(0.0, min(1.0, trust_index))

    # 8. Determine risk level
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
        "triggered_rules": rules
    }

# --- Create FastAPI app ---
app = FastAPI(title="PhishGuard API", description="URL phishing detection", version="1.0")

class URLRequest(BaseModel):
    url: str

@app.post("/predict")
async def predict(request: URLRequest):
    try:
        result = predict_url(request.url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

@app.post("/deep_scan")
async def deep_scan(request: URLRequest):
    try:
        # L1 + L2 result
        l1l2_result = predict_url(request.url)

        # Full sandbox result (RAW)
        sandbox_result = await asyncio.to_thread(analyze_url, request.url)

        # Only the ML input subset for behavioral model
        behavioral_features = {
            "total_requests": sandbox_result.get("total_requests", 0),
            "external_domain_count": sandbox_result.get("external_domain_count", 0),
            "redirect_count": sandbox_result.get("redirect_count", 0),
            "js_requests": sandbox_result.get("js_requests", 0),
            "ip_based_requests": sandbox_result.get("ip_based_requests", 0),
            "suspicious_tld_count": sandbox_result.get("suspicious_tld_count", 0),
            "download_attempts": len(sandbox_result.get("download_attempts", []))
        }

        df = pd.DataFrame([behavioral_features])

        behavioral_prob = behavioral_model.predict_proba(df)[0][1]

        if behavioral_prob > 0.6:
            final_risk = "Phishing"
        elif behavioral_prob > 0.4:
            final_risk = "Suspicious"
        else:
            final_risk = "Safe"

        final_trust = 1 - behavioral_prob

        explanation = (
            "Sandbox executed the URL in an isolated browser and extracted runtime behavior."
        )

        return {
            "scanned_url": request.url,
            "final_risk": final_risk,
            "final_trust_index": final_trust,
            "l1l2": l1l2_result,
            "sandbox": {
                "behavioral_prob": behavioral_prob,
                "behavioral_features": behavioral_features,
                "raw_output": sandbox_result
            },
            "explanation": explanation
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
async def root():
    return {"message": "PhishGuard API is running. Use POST /predict with JSON { 'url': '...' }"}