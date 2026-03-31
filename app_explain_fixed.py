import streamlit as st
import pandas as pd
import numpy as np
import joblib, os, re, tldextract, shap, time, datetime, warnings
import matplotlib.pyplot as plt
import torch
from sentence_transformers import SentenceTransformer
from urllib.parse import urlparse
import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import socket

try:
    import whois
except:
    print("could not import whois")
    whois = None

# 🔧 PATCH: prevent SHAP from misdetecting deep learning models
warnings.filterwarnings("ignore", category=UserWarning)
os.environ["SHAP_ALLOW_DEEP_IMPORTS"] = "false"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"  # suppress TensorFlow noise

# ==========================================================
# === Load Model, Scaler, and Transformer ==================
# ==========================================================
base_path = os.path.dirname(__file__)

rf_model = joblib.load(os.path.join(base_path, "rf_hybrid_minilm.pkl"))
scaler = joblib.load(os.path.join(base_path, "scaler_hybrid.pkl"))
# Workaround: some HuggingFace/transformers loading paths use "meta" tensors
# which cannot be copied with Module.to(). Prefer Module.to_empty() when
# moving modules off the meta device. Patch torch.nn.Module.to to route to
# to_empty() when any parameter lives on the 'meta' device and the target
# move would place it on a real device. This avoids the NotImplementedError
_orig_module_to = torch.nn.Module.to


def _safe_module_to(self, *args, **kwargs):
    try:
        has_meta = any(
            str(getattr(p, "device", "")) == "meta"
            for p in self.parameters(recurse=True)
        )
        # determine target device if provided
        target = kwargs.get("device", args[0] if args else None)
        target_is_meta = str(target) == "meta"
        if has_meta and not target_is_meta and hasattr(self, "to_empty"):
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
    score, rules = 0, []
    ext = tldextract.extract(url)
    if ext.suffix in SUSPICIOUS_TLDS:
        score += 1
        rules.append("Suspicious_TLD")
    if "@" in url:
        score += 1
        rules.append("@_symbol")
    if "http:" in url:
        score += 1
        rules.append("no_https")
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
        "ratio_digits_url": sum(c.isdigit() for c in u) / len(u) if len(u) > 0 else 0,
    }


def extract_top12_features(url):
    features = {}

    # ------------------------
    # URL parsing
    # ------------------------
    parsed = urlparse(url)
    hostname = parsed.netloc

    # 1. length_url
    features["length_url"] = len(url)

    # 2. length_hostname
    features["length_hostname"] = len(hostname)

    # 3. nb_www
    features["nb_www"] = url.count("www")

    # 4. nb_qm
    features["nb_qm"] = url.count("?")

    # 5. ratio_digits_url
    digits = sum(c.isdigit() for c in url)
    features["ratio_digits_url"] = digits / len(url) if len(url) > 0 else 0

    # 6. ip (check if hostname is IP)
    features["ip"] = 1 if re.match(r"\d+\.\d+\.\d+\.\d+", hostname) else 0

    # 7. phish_hints
    features["phish_hints"] = sum(1 for word in PHISH_KEYWORDS if word in url.lower())

    # ------------------------
    # Fetch webpage (optional)
    # ------------------------
    try:
        response = requests.get(url, timeout=5)
        html = response.text
        soup = BeautifulSoup(html, "html.parser")

        # 8. nb_hyperlinks
        links = soup.find_all("a")
        features["nb_hyperlinks"] = len(links)

        # 9. ratio_intHyperlinks
        internal_links = 0
        for link in links:
            href = link.get("href")
            if href and hostname in href:
                internal_links += 1

        features["ratio_intHyperlinks"] = (
            internal_links / len(links) if len(links) > 0 else 0
        )

        # 10. domain_in_title
        title = soup.title.string if soup.title else ""
        features["domain_in_title"] = 1 if hostname in title else 0

    except:
        features["nb_hyperlinks"] = 0
        features["ratio_intHyperlinks"] = 0
        features["domain_in_title"] = 0

    # ------------------------
    # 11. domain_age (optional)
    # ------------------------
    if whois:
        try:
            w = whois.whois(hostname)
            creation_date = w.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                age_days = (datetime.now() - creation_date).days
                features["domain_age"] = age_days
            else:
                features["domain_age"] = 0
        except:
            features["domain_age"] = 0
    else:
        features["domain_age"] = 0

    # ------------------------
    # 12. google_index (mock)
    # ------------------------
    # Real Google index requires API/scraping
    # Placeholder: assume indexed if response OK
    features["google_index"] = (
        1 if "response" in locals() and response.status_code == 200 else 0
    )

    return features


# ==========================================================
# === Prediction Function ==================================
# ==========================================================
def predict_url_simple(url):
    global X_hybrid  # for debugging purposes
    emb = minilm_model.encode([url], show_progress_bar=False)
    feat = np.array(list(extract_basic_features(url).values())).reshape(1, -1)
    pad = np.zeros((1, scaler.mean_.shape[0] - feat.shape[1]))
    num_scaled = np.hstack([feat, pad])
    X_hybrid = np.hstack([emb, num_scaled])
    prob = rf_model.predict_proba(X_hybrid)[0][1]
    rule_score, rules = compute_rule_score(url)
    prob_coef = 0.4
    rule_coef = 0.6
    trust_index = prob_coef * prob + rule_coef * (1 - rule_score)
    trust_index = max(0.0, min(1.0, trust_index))
    if trust_index >= 0.65:
        risk = "Safe"
    elif trust_index >= 0.35:
        risk = "Suspicious"
    else:
        risk = "Phishing"
    return prob, rule_score, trust_index, risk, rules, X_hybrid, rule_coef, prob_coef


# ==========================================================
# === SHAP Explainability ==================================
# ==========================================================
def explain_url_shap(X_hybrid):
    """
    Safely compute SHAP values for the RandomForest model.
    Avoids deep learning detection issues.
    """
    try:
        explainer = shap.TreeExplainer(
            rf_model, feature_perturbation="tree_path_dependent"
        )
        shap_values = explainer.shap_values(X_hybrid)

        if isinstance(shap_values, (list, tuple)):
            arr = shap_values[1] if len(shap_values) > 1 else shap_values[0]
        else:
            arr = shap_values
        vals = shap_values[0, :, 1]

        if vals is None:
            raise ValueError(f"Unhandled shap_values structure: {type(shap_values)}")

        abs_vals = np.abs(vals)
        top_idx = np.argsort(abs_vals)[-10:][::-1]
        top_vals = vals[top_idx]
        top_labels = [f"Feature_{i}" for i in top_idx]
        fig, ax = plt.subplots(figsize=(7, 4))
        colors = ["red" if v > 0 else "green" for v in top_vals]
        ax.barh(top_labels[::-1], top_vals[::-1], color=colors[::-1])
        ax.set_xlabel("SHAP Value (Impact on Phishing Prediction)")
        ax.set_title("Top 10 Influencing Features")
        plt.tight_layout()
        st.pyplot(fig)

        return shap_values, vals
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
    fig, ax = plt.subplots(figsize=(7, 4))
    colors = ["red" if v > np.mean(importances) else "green" for v in top_vals]
    ax.barh(top_labels[::-1], top_vals[::-1], color=colors[::-1])
    ax.set_xlabel("Approx. Feature Importance (Impact on Prediction)")
    ax.set_title("Top 10 Influencing Features (Fallback Mode)")
    plt.tight_layout()
    st.pyplot(fig)


# ==========================================================
# === Streamlit UI =========================================
# ==========================================================
st.set_page_config(
    page_title="NoPhish – Explainable Detector (Fixed)",
    page_icon="🧠",
    layout="centered",
)
st.title("🧠 NoPhish – Explainable Phishing URL Detector")
st.markdown(
    "v5.1 – Now with SHAP explainability! Enter a URL to see the prediction and which features influenced it the most."
)

url_input = st.text_input("🔗 Enter URL:", placeholder="https://example.com")
analyze_btn = st.button("Analyze & Explain")

if analyze_btn and url_input.strip():
    with st.spinner("Running model & SHAP analysis..."):
        prob, rule_score, trust_index, risk, rules, X_hybrid, rule_coef, prob_coef = (
            predict_url_simple(url_input)
        )
        print(prob, " + ", rule_score, " = ", trust_index)
        time.sleep(1.0)

    color = {"Safe": "green", "Suspicious": "orange", "Phishing": "red"}[risk]
    st.markdown(
        f"### 🧾 Result: <span style='color:{color};font-size:22px'><b>{risk}</b></span>",
        unsafe_allow_html=True,
    )
    st.progress(int(trust_index * 100))
    st.markdown("### Debug Info")
    st.write(f"**Trust Index:** {trust_index:.3f}")
    st.write(f"**Model Probability (Phishing):** {prob:.3f}")
    st.write(f"**Rule Score:** {rule_score:.3f}")
    st.write(f"**Triggered Rules:** {', '.join(rules) if rules else 'None'}")
    st.write(f"**Checked at:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    st.markdown("---")
    st.subheader("📊 Explanation: Feature Influence (SHAP)")
    shap_values, vals = explain_url_shap(X_hybrid)
    st.success("✅ Explanation generated successfully.")
    with st.expander("Debug Info"):
        st.write("Model expects features:", rf_model.n_features_in_)
        st.write("X_hybrid shape:", X_hybrid.shape)
        st.write("SHAP shape:", np.array(shap_values).shape)
        st.write("Length of SHAP vector:", len(vals))
        st.write("Non-zero SHAP features:", np.count_nonzero(vals))
        st.write(
            f"{prob_coef} x {prob:.2f} + {rule_coef} x {rule_score:.2f} = {trust_index:.2f}"
        )
        st.write("prob", " + ", "rule_score", " = ", "trust_index")
        st.write(rules)
        print(shap_values)
        print(vals)
        print(prob)
        print(rule_score)
else:
    st.info("Enter a URL and click **Analyze & Explain** to begin.")
