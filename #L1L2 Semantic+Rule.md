# Hybrid Explainable Phishing URL Detection

## Project Summary

A hybrid phishing detection system combining:
- Transformer-based semantic analysis (MiniLM)
- Handcrafted structural features
- Cybersecurity rule engine

Outputs:
- Trust Index (0–1)
- Classification: Safe / Suspicious / Phishing
- Explainable reasoning

---

## Architecture

URL → Feature Extraction  
→ (Semantic + Structural + Rules)  
→ Hybrid Vector (471 features)  
→ Random Forest  
→ Trust Index  
→ Triage Classification  
→ Explainability + Streamlit App  

---

## Modules

### 1. Semantic Layer
- MiniLM transformer
- 384-d embeddings

### 2. Structural Layer
- 87 handcrafted features

### 3. Rule Engine
- Detects suspicious TLDs, keywords, symbols
- Outputs rule_score

### 4. ML Model
- Random Forest classifier

### 5. Trust Index
TrustIndex = (0.7 × ML Prob) + (0.3 × (1 − Rule Score))

### 6. Triage System
- Safe
- Suspicious
- Phishing

### 7. Explainability
- SHAP + feature importance

---

## Implementation Timeline

Day 1: Baseline ML  
Day 2: Transformer integration  
Day 3: Rule engine + Trust Index  
Day 4: Streamlit app  
Day 5: Explainability + reports  

---

## Novelty

- Trust Index (AI + cybersecurity fusion)
- Hybrid 3-layer architecture
- Explainable phishing detection
- Real-time application

---

## Technologies

Python, Scikit-learn, Sentence Transformers, SHAP, Streamlit

---

## Conclusion

An explainable, hybrid AI system that detects phishing URLs and provides human-readable trust scores in real time.
