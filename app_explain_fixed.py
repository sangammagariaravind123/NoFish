import streamlit as st
import pandas as pd
import numpy as np
import joblib, os, re, tldextract, shap, time, datetime, warnings
import matplotlib.pyplot as plt
import torch
from sentence_transformers import SentenceTransformer
from urllib.parse import urlparse

# 🔧 PATCH: prevent SHAP from misdetecting deep learning models
warnings.filterwarnings("ignore", category=UserWarning)
os.environ["SHAP_ALLOW_DEEP_IMPORTS"] = "false"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"   # suppress TensorFlow noise

# ==========================================================
# === Load Model, Scaler, and Transformer ==================
# ==========================================================
base_path = os.path.dirname(__file__)

rf_model = joblib.load(os.path.join(base_path, "rf_hybrid_minilm.pkl"))
scaler   = joblib.load(os.path.join(base_path, "scaler_hybrid.pkl"))
# Workaround: some HuggingFace/transformers loading paths use "meta" tensors
# which cannot be copied with Module.to(). Prefer Module.to_empty() when
# moving modules off the meta device. Patch torch.nn.Module.to to route to
# to_empty() when any parameter lives on the 'meta' device and the target
# move would place it on a real device. This avoids the NotImplementedError
_orig_module_to = torch.nn.Module.to
def _safe_module_to(self, *args, **kwargs):
    try:
        has_meta = any(str(getattr(p, 'device', '')) == 'meta' for p in self.parameters(recurse=True))
        # determine target device if provided
        target = kwargs.get('device', args[0] if args else None)
        target_is_meta = (str(target) == 'meta')
        if has_meta and not target_is_meta and hasattr(self, 'to_empty'):
            return self.to_empty(*args, **kwargs)
    except Exception:
        pass
    return _orig_module_to(self, *args, **kwargs)

torch.nn.Module.to = _safe_module_to

# Now load the sentence-transformer model
minilm_model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

# ==========================================================
# === Cybersecurity Rule Engine ============================
# ==========================================================
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

# ==========================================================
# === Basic Numeric Features ===============================
# ==========================================================
def extract_basic_features(url):
    u = str(url)
    return {
        "length_url": len(u),
        "nb_dots": u.count("."),
        "nb_hyphens": u.count("-"),
        "https_token": 1 if "https" in u.lower() else 0,
        "ratio_digits_url": sum(c.isdigit() for c in u)/len(u) if len(u)>0 else 0,
    }

# ==========================================================
# === Prediction Function ==================================
# ==========================================================
def predict_url_simple(url):
    emb  = minilm_model.encode([url], show_progress_bar=False)
    feat = np.array(list(extract_basic_features(url).values())).reshape(1,-1)
    pad  = np.zeros((1, scaler.mean_.shape[0]-feat.shape[1]))
    num_scaled = np.hstack([feat, pad])
    X_hybrid = np.hstack([emb, num_scaled])
    prob = rf_model.predict_proba(X_hybrid)[0][1]
    rule_score, rules = compute_rule_score(url)
    trust_index = 0.7*prob + 0.3*(1-rule_score)
    trust_index = max(0.0, min(1.0, trust_index))
    if trust_index >= 0.55: risk="Safe"
    elif trust_index >= 0.35: risk="Suspicious"
    else: risk="Phishing"
    return prob, rule_score, trust_index, risk, rules, X_hybrid

# ==========================================================
# === SHAP Explainability ==================================
# ==========================================================
def explain_url_shap(X_hybrid):
    """
    Safely compute SHAP values for the RandomForest model.
    Avoids deep learning detection issues.
    """
    try:
        explainer = shap.TreeExplainer(rf_model, feature_perturbation="tree_path_dependent")
        shap_values = explainer.shap_values(X_hybrid)
        vals = None
        # Robust handling: shap_values may be a list (one per class) or a single
        # ndarray with shape (n_samples, n_features). Handle common cases.
        if isinstance(shap_values, (list, tuple)):
            arr = shap_values[1] if len(shap_values) > 1 else shap_values[0]
        else:
            arr = shap_values

        # Now normalize arr to a 1D feature vector for the first sample
        if hasattr(arr, 'ndim'):
            if arr.ndim == 3:
                # (classes, n_samples, n_features)
                if arr.shape[0] > 1:
                    vals = arr[1][0]
                else:
                    vals = arr[0][0]
            elif arr.ndim == 2:
                # (n_samples, n_features)
                vals = arr[0]
            elif arr.ndim == 1:
                vals = arr
        else:
            vals = np.array(arr).flatten()

        if vals is None:
            raise ValueError(f"Unhandled shap_values structure: {type(shap_values)}")

        abs_vals = np.abs(vals)
        top_idx = np.argsort(abs_vals)[-10:][::-1]
        top_vals = vals[top_idx]
        top_labels = [f"Feature_{i}" for i in top_idx]
        fig, ax = plt.subplots(figsize=(7,4))
        colors = ["red" if v>0 else "green" for v in top_vals]
        ax.barh(top_labels[::-1], top_vals[::-1], color=colors[::-1])
        ax.set_xlabel("SHAP Value (Impact on Phishing Prediction)")
        ax.set_title("Top 10 Influencing Features")
        plt.tight_layout()
        st.pyplot(fig)
    except Exception as e:
        st.error(f"⚠️ SHAP visualization failed:\n{e}")
        st.info("Falling back to RandomForest feature importances.")
        explain_fallback()

# ==========================================================
# === Fallback if SHAP still fails ==========================
# ==========================================================
def explain_fallback():
    importances = rf_model.feature_importances_
    top_idx = np.argsort(importances)[-10:][::-1]
    top_vals = importances[top_idx]
    top_labels = [f"Feature_{i}" for i in top_idx]
    fig, ax = plt.subplots(figsize=(7,4))
    colors = ["red" if v>np.mean(importances) else "green" for v in top_vals]
    ax.barh(top_labels[::-1], top_vals[::-1], color=colors[::-1])
    ax.set_xlabel("Approx. Feature Importance (Impact on Prediction)")
    ax.set_title("Top 10 Influencing Features (Fallback Mode)")
    plt.tight_layout()
    st.pyplot(fig)

# ==========================================================
# === Streamlit UI =========================================
# ==========================================================
st.set_page_config(page_title="PhishTriage – Explainable Detector (Fixed)", page_icon="🧠", layout="centered")
st.title("🧠 PhishTriage – Explainable Phishing URL Detector")
st.markdown("v4.0 – Now with SHAP explainability! Enter a URL to see the prediction and which features influenced it the most.")

url_input = st.text_input("🔗 Enter URL:", placeholder="https://example.com")
analyze_btn = st.button("Analyze & Explain")

if analyze_btn and url_input.strip():
    with st.spinner("Running model & SHAP analysis..."):
        prob, rule_score, trust_index, risk, rules, X_hybrid = predict_url_simple(url_input)
        time.sleep(1.0)

    color = {"Safe":"green","Suspicious":"orange","Phishing":"red"}[risk]
    st.markdown(f"### 🧾 Result: <span style='color:{color};font-size:22px'><b>{risk}</b></span>", unsafe_allow_html=True)
    st.progress(int(trust_index*100))
    st.write(f"**Trust Index:** {trust_index:.3f}")
    st.write(f"**Model Probability (Phishing):** {prob:.3f}")
    st.write(f"**Rule Score:** {rule_score:.3f}")
    st.write(f"**Triggered Rules:** {', '.join(rules) if rules else 'None'}")
    st.write(f"**Checked at:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    st.markdown("---")
    st.subheader("📊 Explanation: Feature Influence (SHAP)")
    explain_url_shap(X_hybrid)
    st.success("✅ Explanation generated successfully.")
else:
    st.info("Enter a URL and click **Analyze & Explain** to begin.")
