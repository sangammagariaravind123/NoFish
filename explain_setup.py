#!/usr/bin/env python3
"""
explain_setup.py

Day-5 Part-1 (Setup & SHAP Background)
Idiot-proof script that:
 - installs missing packages (shap, matplotlib, seaborn)
 - optionally mounts Google Drive (if running in Colab)
 - loads model and scaler (rf_hybrid_minilm.pkl, scaler_hybrid.pkl)
 - loads SentenceTransformer model (all-MiniLM-L6-v2)
 - tests one embedding + one inference
 - creates and saves a SHAP TreeExplainer as shap_explainer.joblib

Usage:
 - Place this file where your model files are (or run in Colab after mounting Drive
   and setting base_path accordingly).
 - Run: python explain_setup.py
"""

import sys, os, subprocess, json, time
from pathlib import Path

# -----------------------
# 1) Helper: pip installer (idempotent)
# -----------------------
def pip_install(packages):
    """
    Install a list of pip packages. Skips if already importable.
    """
    for pkg in packages:
        name = pkg.split("==")[0]
        try:
            __import__(name)
            print(f"[OK] Already installed: {name}")
        except Exception:
            print(f"[INSTALL] Installing {pkg} ...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
            print(f"[OK] Installed {pkg}")

# Minimal safe set for SHAP / plotting / sentence-transformers
required_pkgs = [
    "shap==0.46.0",          # stable SHAP version (works with sklearn RF)
    "matplotlib==3.9.2",
    "seaborn==0.13.2",
    "sentence-transformers==2.2.2",  # smaller, stable release; if already used 3.x earlier in project, it still works
    "joblib",
    "tldextract"
]

# Try to install missing packages (this is safe to run multiple times)
try:
    pip_install(required_pkgs)
except Exception as e:
    print("✖ Failed while installing packages. Error:")
    print(e)
    print("→ If installation failed, try running the install line manually:")
    print("   pip install " + " ".join(required_pkgs))
    sys.exit(1)

# -----------------------
# 2) Imports (post-install)
# -----------------------
import joblib
import numpy as np
import pandas as pd
import shap
import matplotlib.pyplot as plt
from sentence_transformers import SentenceTransformer
import sklearn
from sklearn.ensemble import RandomForestClassifier

print("\n[INFO] Imported core libraries. Versions:")
print("  python:", sys.version.splitlines()[0])
print("  sklearn:", sklearn.__version__)
print("  shap:", shap.__version__)
print("  sentence_transformers:", getattr(__import__("sentence_transformers"), "__version__", "unknown"))

# -----------------------
# 3) Optional: Google Drive mount hint for Colab users
# -----------------------
IN_COLAB = False
try:
    import google.colab
    IN_COLAB = True
except Exception:
    IN_COLAB = False

if IN_COLAB:
    print("\n[NOTICE] Running inside Google Colab. The script will *not* auto-mount Drive.")
    print("If your model files are in Drive, run: from google.colab import drive; drive.mount('/content/drive') and set base_path accordingly.")
    # Default base path in Colab (user must adjust if using Drive)
    base_path = "/content/drive/MyDrive/Phishing_Project/data"
else:
    # Local run: use current script directory as default base path
    base_path = os.path.dirname(os.path.abspath(__file__))

print("\n[INFO] Using base_path =", base_path)
os.makedirs(base_path, exist_ok=True)

# -----------------------
# 4) Verify model files exist
# -----------------------
expected_rf = os.path.join(base_path, "rf_hybrid_minilm.pkl")
expected_scaler = os.path.join(base_path, "scaler_hybrid.pkl")
missing = []
for p in (expected_rf, expected_scaler):
    if not os.path.exists(p):
        missing.append(p)

if missing:
    print("\n✖ ERROR: Required files not found in base_path.")
    print("Expected these files (place them in the base_path or change base_path):")
    for m in missing:
        print("  -", m)
    print("\nIf you are in Colab and your files are in Drive, mount Drive and set base_path accordingly.")
    sys.exit(1)

print("\n[OK] Found required model files.")

# -----------------------
# 5) Load model & scaler safely
# -----------------------
try:
    rf_model = joblib.load(expected_rf)
    print("[OK] Loaded RandomForest model from:", expected_rf)
except Exception as e:
    print("✖ Failed to load RandomForest model. Error:")
    print(e)
    sys.exit(1)

try:
    scaler = joblib.load(expected_scaler)
    print("[OK] Loaded scaler from:", expected_scaler)
except Exception as e:
    print("✖ Failed to load scaler. Error:")
    print(e)
    sys.exit(1)

# Quick type check
if not hasattr(rf_model, "predict_proba"):
    print("✖ Warning: loaded rf_model does not have predict_proba(). Check model file.")
else:
    print("  rf_model supports predict_proba()")

# -----------------------
# 6) Load Sentence-BERT (MiniLM)
# -----------------------
print("\n[INFO] Loading SentenceTransformer model: all-MiniLM-L6-v2 (this may take ~10-60s depending on environment)...")
try:
    sbert = SentenceTransformer("all-MiniLM-L6-v2")
    print("[OK] SentenceTransformer loaded.")
except Exception as e:
    print("✖ Failed to load SentenceTransformer.")
    print("Error:", e)
    print("If you're offline or the environment blocks downloads, pre-download weights or run locally with internet.")
    sys.exit(1)

# -----------------------
# 7) Quick embedding + inference smoke-test
# -----------------------
print("\n[INFO] Running a quick embedding + inference test (sanity check).")
sample_urls = ["https://www.google.com", "https://paypal-login.tk"]
try:
    emb = sbert.encode(sample_urls, show_progress_bar=False)
    print("  Embeddings shape:", emb.shape, "(expected (2, 384))")
except Exception as e:
    print("✖ Embedding failed. Error:", e)
    sys.exit(1)

# Build a dummy numeric vector padded with zeros of the right length for scaler
if not hasattr(scaler, "mean_"):
    print("✖ Scaler missing 'mean_' attribute; cannot infer numeric dimension.")
    sys.exit(1)
num_dim = scaler.mean_.shape[0]
print("  Numeric feature dimension expected by scaler:", num_dim)
dummy_numeric = np.zeros((emb.shape[0], num_dim))
X_hybrid = np.hstack([emb, dummy_numeric])
print("  Hybrid feature test shape:", X_hybrid.shape)

# Test model predict_proba
try:
    proba = rf_model.predict_proba(X_hybrid)  # returns [[p0,p1],...]
    print("  Model predict_proba OK. Sample output (first row):", proba[0][:5], " ...")
except Exception as e:
    print("✖ RF predict_proba failed. Error:", e)
    print("Tip: check hybrid feature dimension expected by RF vs provided X_hybrid.")
    sys.exit(1)

# -----------------------
# 8) Create SHAP TreeExplainer and save it
# -----------------------
explainer_path = os.path.join(base_path, "shap_explainer.joblib")
print("\n[INFO] Initializing SHAP TreeExplainer on the RandomForest (this is quick).")
try:
    # TreeExplainer works well with tree-based models (RandomForest)
    explainer = shap.TreeExplainer(rf_model)
    # quick compute to warm up internal structures with our sample X_hybrid
    shap_vals = explainer.shap_values(X_hybrid[:1])
    print("  SHAP TreeExplainer created. shap_values shape example:", [a.shape for a in shap_vals])
    # save explainer to disk for later use
    joblib.dump(explainer, explainer_path)
    print(f"[OK] SHAP explainer saved to: {explainer_path}")
except Exception as e:
    print("✖ Failed to create or save SHAP explainer. Error:", e)
    # still continue because SHAP can be created on-the-fly later
    if os.path.exists(explainer_path):
        print("[NOTE] Existing explainer file present.")
    else:
        print("[NOTE] You can still run SHAP later with explainer = shap.TreeExplainer(rf_model) in your notebook.")
    # not fatal; continue

# -----------------------
# 9) Save a short JSON manifest (helpful later)
# -----------------------
manifest = {
    "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
    "base_path": base_path,
    "rf_model_file": expected_rf,
    "scaler_file": expected_scaler,
    "shap_explainer_file": explainer_path if os.path.exists(explainer_path) else None,
    "sbert_model": "all-MiniLM-L6-v2"
}
manifest_path = os.path.join(base_path, "explain_setup_manifest.json")
with open(manifest_path, "w") as f:
    json.dump(manifest, f, indent=2)
print("\n[OK] Manifest saved to:", manifest_path)

# -----------------------
# 10) Final sanity summary & next-step hints
# -----------------------
print("\n✅ All done for Day-5 Part-1 (Setup & SHAP readiness). Summary:")
print(" - Base path:", base_path)
print(" - RF model loaded:", expected_rf)
print(" - Scaler loaded:", expected_scaler)
print(" - SentenceTransformer ready (all-MiniLM-L6-v2)")
print(" - SHAP explainer file:", explainer_path if os.path.exists(explainer_path) else "not saved (create on-the-fly later)")
print("\nNext steps (Day-5 Part-2):")
print("  1) Use the saved explainer (shap_explainer.joblib) or create new TreeExplainer(rf_model).")
print("  2) For any URL, compute its hybrid X_hybrid (embedding + scaled numeric) then call explainer.shap_values(X_hybrid).")
print("  3) Visualize top SHAP values as bar chart in Streamlit (I will provide the exact complete app file in Part-2).")

print("\nIf you see any errors above, copy the full stack trace and paste it here; I will debug it quickly.")
