import streamlit as st
import pandas as pd
import numpy as np
import time
from datetime import datetime
import os, re, joblib, tldextract
from urllib.parse import urlparse
from sentence_transformers import SentenceTransformer

# === Load Model and Scaler ===
base_path = os.path.dirname(__file__)

rf_model = joblib.load(os.path.join(base_path, "rf_hybrid_minilm.pkl"))
scaler = joblib.load(os.path.join(base_path, "scaler_hybrid.pkl"))
minilm_model = SentenceTransformer("all-MiniLM-L6-v2")

# === Rule Engine ===
SUSPICIOUS_TLDS = ["tk","ml","ga","cf","gq","xyz","top","club","work","zip","link","cn"]
PHISHING_KEYWORDS = ["login","verify","update","secure","account","bank","payment","signin","confirm"]
URL_SHORTENERS = ["bit.ly","tinyurl","goo.gl","t.co","is.gd","buff.ly","adf.ly","shorturl"]

def compute_rule_score(url):
    score, rules = 0, []
    ext = tldextract.extract(url)
    if ext.suffix in SUSPICIOUS_TLDS: score += 1; rules.append("Suspicious_TLD")
    if "@" in url: score += 1; rules.append("@_symbol")
    if url.count(".") > 4: score += 1; rules.append("Excess_subdomains")
    if any(k in url.lower() for k in PHISHING_KEYWORDS): score += 1; rules.append("Keyword_match")
    if any(short in url.lower() for short in URL_SHORTENERS): score += 1; rules.append("Shortener")
    return score/5, rules

# === Basic Numeric Feature Extractor ===
def extract_basic_features(url):
    u = str(url)
    return {
        "length_url": len(u),
        "nb_dots": u.count("."),
        "nb_hyphens": u.count("-"),
        "https_token": 1 if "https" in u.lower() else 0,
        "ratio_digits_url": sum(c.isdigit() for c in u)/len(u) if len(u)>0 else 0,
    }

# === Mini Predict Function ===
def predict_url_simple(url):
    emb = minilm_model.encode([url], show_progress_bar=False)
    feat = np.array(list(extract_basic_features(url).values())).reshape(1,-1)
    pad = np.zeros((1, scaler.mean_.shape[0]-feat.shape[1]))
    num_scaled = np.hstack([feat, pad])
    prob = rf_model.predict_proba(np.hstack([emb, num_scaled]))[0][1]
    rule_score, rules = compute_rule_score(url)
    trust_index = 0.7*prob + 0.3*(1-rule_score)
    trust_index = max(0.0, min(1.0, trust_index))
    if trust_index >= 0.55: risk="Safe"
    elif trust_index >= 0.35: risk="Suspicious"
    else: risk="Phishing"
    return prob, rule_score, trust_index, risk, rules

# === Streamlit UI ===
st.set_page_config(page_title="PhishTriage – URL Detector", page_icon="🛡️", layout="centered")

st.title("🛡️ PhishTriage – Real-Time Phishing URL Detector")
st.markdown("Enter any URL below to analyze its risk level using our hybrid AI + Cybersecurity model.")

url_input = st.text_input("🔗 Enter URL here:", placeholder="https://example.com")
check_btn = st.button("Check URL")

if check_btn and url_input.strip():
    with st.spinner("Analyzing... Please wait"):
        prob, rule_score, trust_index, risk, rules = predict_url_simple(url_input)
        time.sleep(1.5)
    st.subheader("Results:")
    color = {"Safe":"green","Suspicious":"orange","Phishing":"red"}[risk]
    st.markdown(f"**Risk Level:** <span style='color:{color};font-size:22px'><b>{risk}</b></span>", unsafe_allow_html=True)
    st.progress(int(trust_index*100))
    st.write(f"**Trust Index:** {trust_index:.3f}")
    st.write(f"**Model Probability (Phishing):** {prob:.3f}")
    st.write(f"**Rule Score:** {rule_score:.3f}")
    st.write(f"**Triggered Rules:** {', '.join(rules) if rules else 'None'}")
    st.write(f"Checked at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    st.success("✅ Analysis completed successfully!")
else:
    st.info("Enter a URL and click **Check URL** to begin.")
