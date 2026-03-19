# 🛡️ URL Behavior Sandbox + ML Phishing Detection

A hybrid phishing detection system using **dynamic sandbox analysis + machine learning**.

---

## 🚀 Overview

This project:
- Executes URLs in a sandbox (Playwright + Docker)
- Extracts runtime behavioral features
- Combines with static URL features
- Trains an ML model (Random Forest)
- Provides prediction via CLI and API
- Outputs risk score (0–100)

---

## 🧱 Pipeline

```
URL
 ↓
Sandbox (Playwright)
 ↓
Feature Extraction
 ↓
Dataset (CSV)
 ↓
ML Model (Random Forest)
 ↓
Prediction + Risk Score
 ↓
API / CLI Output
```

---

## 📊 Extracted Features

### 🔹 Dynamic (Sandbox)
- total_requests
- external_domain_count
- redirect_count
- js_requests
- ip_based_requests
- suspicious_tld_count
- download_attempts

### 🔹 Static (URL)
- 88 features

---

## ⚙️ Setup

### Build Docker image
```bash
docker build -t url-sandbox .
```

### Run sandbox
```bash
docker run --rm url-sandbox
docker run --rm -v ${PWD}:/app url-sandbox (if rerunning)
```

Output:
```
results.json
```

---

## 🧪 Dataset Preparation

```bash
python prepare_dataset.py
```

Output:
```
dataset.csv
```

---

## 🏷️ Label Data

Manually or auto-label:

```bash
python auto_label.py
```

---

## 🤖 Train Model

```bash
python train_model.py
```

Outputs:
- model.pkl
- feature_importance.png
- metrics.png
- confusion_matrix.png

---

## 🔍 Predict (CLI)

```bash
python predict.py
```

---

<!-- ## 🌐 API Server

```bash
uvicorn api:app --reload
``` -->

Open:
```
http://127.0.0.1:8000/docs
```

---

## 📈 Risk Scoring

Instead of binary output:

```
Risk Score = 0–100
```

Example:
```
example.com → 12 → LEGIT
phish.xyz → 87 → PHISHING
```

---

## ⚡ Parallel Scanning

Speeds up dataset generation:

```python
from concurrent.futures import ThreadPoolExecutor
```

---

## 🔐 Security Features

- Docker isolation
- Headless browser
- Downloads blocked
- No persistent storage
- No hardware access
- Timeout enforced

---

## 📊 Model

- Algorithm: Random Forest
- Input: Hybrid features (static + dynamic)
- Output: phishing / legit + probability

---

## 🎓 Key Highlights

- Hybrid phishing detection
- Dynamic behavioral analysis
- Risk-based scoring
- API deployment
- Parallel sandbox execution

---

<!-- ## 🧠 Viva Explanation

> This system uses a sandboxed headless browser to extract runtime behavioral features from URLs and combines them with static URL features to train a machine learning model for phishing detection, enhanced with probabilistic risk scoring. -->

---

## ⚠️ Disclaimer

For academic and research use only.  
Run only inside isolated environments.

---

## 🏁 Run Summary

```bash
docker run --rm -v ${PWD}:/app url-sandbox
python prepare_dataset.py
python train_model.py
uvicorn api:app --reload
```

---

## 🔥 Future Work

- Web dashboard UI
- PhishTank integration
- Real-time monitoring
- Advanced feature engineering
<!-- - Model optimization (XGBoost) -->