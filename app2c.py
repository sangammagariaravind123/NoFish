import streamlit as st
import pandas as pd
import numpy as np
import time, csv, datetime, os, re, joblib, tldextract
from urllib.parse import urlparse
from sentence_transformers import SentenceTransformer

base_path = os.path.dirname(__file__)
rf_model = joblib.load(os.path.join(base_path, "rf_hybrid_minilm.pkl"))
scaler   = joblib.load(os.path.join(base_path, "scaler_hybrid.pkl"))
minilm_model = SentenceTransformer("all-MiniLM-L6-v2")

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

def extract_features(url):
    u = str(url)
    return {
        "length_url": len(u),
        "nb_dots": u.count("."),
        "nb_hyphens": u.count("-"),
        "https_token": 1 if "https" in u.lower() else 0,
        "ratio_digits_url": sum(c.isdigit() for c in u)/len(u) if len(u)>0 else 0,
    }

def predict_url_simple(url):
    emb  = minilm_model.encode([url], show_progress_bar=False)
    feat = np.array(list(extract_features(url).values())).reshape(1,-1)
    pad  = np.zeros((1, scaler.mean_.shape[0]-feat.shape[1]))
    num_scaled = np.hstack([feat, pad])
    prob = rf_model.predict_proba(np.hstack([emb, num_scaled]))[0][1]
    rule_score, rules = compute_rule_score(url)
    trust_index = 0.7*prob + 0.3*(1-rule_score)
    trust_index = max(0.0, min(1.0, trust_index))
    if trust_index >= 0.55: risk="Safe"
    elif trust_index >= 0.35: risk="Suspicious"
    else: risk="Phishing"
    return prob, rule_score, trust_index, risk, rules

log_path = os.path.join(base_path, "live_prediction_logs.csv")
def log_result(url, prob, rule_score, trust_index, risk, rules):
    write_header = not os.path.exists(log_path)
    with open(log_path, "a", newline="") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(["timestamp","url","ml_prob","rule_score","trust_index","risk_level","triggered_rules"])
        writer.writerow([
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            url, round(prob,4), round(rule_score,4), round(trust_index,4),
            risk, ";".join(rules)
        ])

st.set_page_config(page_title="PhishTriage – URL Detector", page_icon="🛡️", layout="centered")
st.title("🛡️ PhishTriage – Real-Time Phishing URL Detector")
st.markdown("Enter a single URL or upload a CSV for bulk testing.")

# --- Single URL ---
url_input = st.text_input("🔗 Enter URL here:", placeholder="https://example.com")
check_btn = st.button("Check URL")

if check_btn and url_input.strip():
    with st.spinner("Analyzing... Please wait"):
        prob, rule_score, trust_index, risk, rules = predict_url_simple(url_input)
        time.sleep(1)
    color = {"Safe":"green","Suspicious":"orange","Phishing":"red"}[risk]
    st.markdown(f"**Risk Level:** <span style='color:{color};font-size:22px'><b>{risk}</b></span>", unsafe_allow_html=True)
    st.progress(int(trust_index*100))
    st.write(f"**Trust Index:** {trust_index:.3f}")
    st.write(f"**Model Probability (Phishing):** {prob:.3f}")
    st.write(f"**Rule Score:** {rule_score:.3f}")
    st.write(f"**Triggered Rules:** {', '.join(rules) if rules else 'None'}")
    st.write(f"Checked at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log_result(url_input, prob, rule_score, trust_index, risk, rules)
    st.success("✅ Logged and completed.")

# --- Bulk Upload ---
st.markdown("---")
st.subheader("📂 Bulk URL Testing")

uploaded = st.file_uploader("Upload CSV (must contain column 'url')", type=['csv'])
if uploaded is not None:
    data = pd.read_csv(uploaded)
    if 'url' not in data.columns:
        st.error("CSV must contain column named 'url'.")
    else:
        st.info(f"Processing {len(data)} URLs ...")
        results = []
        progress = st.progress(0)
        for i, u in enumerate(data['url']):
            prob, rule_score, ti, risk, rules = predict_url_simple(str(u))
            results.append({
                "url": u,
                "ml_prob": prob,
                "rule_score": rule_score,
                "trust_index": ti,
                "risk_level": risk,
                "triggered_rules": ", ".join(rules)
            })
            log_result(u, prob, rule_score, ti, risk, rules)
            progress.progress(int((i+1)/len(data)*100))
        res_df = pd.DataFrame(results)
        out_csv = os.path.join(base_path, "bulk_results.csv")
        res_df.to_csv(out_csv, index=False)
        st.dataframe(res_df.head(10))
        st.success(f"✅ Bulk analysis complete. Saved to {out_csv}")





# --- Summary Report Button ---
st.markdown("---")
st.subheader("📊 View Summary Report")

if st.button("Show Summary"):
    if os.path.exists(log_path):
        df = pd.read_csv(log_path)
        counts = df['risk_level'].value_counts()
        st.bar_chart(counts)
        st.write("**Summary:**")
        st.dataframe(counts.rename("Count"))
        st.caption(f"Total entries: {len(df)}  •  Log path: {log_path}")
    else:
        st.warning("No log file found yet. Run a few checks first!")
