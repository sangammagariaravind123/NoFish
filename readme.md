# NoPhish

NoPhish is a three-level explainable phishing URL detection system built as a Chrome extension with a local FastAPI backend. It combines fast URL analysis, optional sandbox-based deep scanning, SHAP explanations, and browser-side history/settings workflows.

## Overview

The system has two main runtime parts:

- A Chrome extension for popup scanning, warning flow, dashboard/history, settings, and optional account-linked sync
- A local FastAPI service that runs the ML pipeline, SHAP generation, and Playwright-backed deep scans on `http://localhost:8000`

## Key Features

- L1+L2 fast scan using MiniLM semantic embeddings, handcrafted URL features, Random Forest, and rule-based scoring
- L3 deep scan using sandbox-based behavioral analysis with Playwright
- SHAP-based explainability for feature contribution analysis
- Extension UI with popup, dashboard, history, settings, auth callback, and warning page
- Local history/settings storage with optional Supabase Auth + Postgres sync
- Control rules for allow/block decisions and auto-block behavior

## System Architecture

1. The extension captures the active tab URL.
2. A fast scan calls `POST /predict` on the local FastAPI backend.
3. The backend combines MiniLM embeddings, engineered URL features, and rule scores to classify the URL.
4. If the user or security mode requires deeper verification, the extension triggers `POST /deep_scan`.
5. The deep-scan path uses Playwright sandbox execution to collect behavioral signals and score the page with the L3 model.
6. Detailed analysis can request SHAP explanations from the backend and store results in local history or optional Supabase-backed sync.

## Tech Stack

- Python 3.12
- FastAPI + Uvicorn
- Sentence Transformers (`all-MiniLM-L6-v2`)
- scikit-learn, PyTorch, SHAP, pandas, numpy
- Playwright (Chromium)
- Chrome Extension Manifest V3
- JavaScript / HTML / CSS
- Supabase Auth + Postgres (optional)
- esbuild for bundling the Supabase browser client

## Repository Structure

```text
NoFish/
├─ api/                    # FastAPI app, model artifacts, feature extraction, sandbox screenshot route
├─ extension/              # Chrome extension source (popup, dashboard, history, settings, warning, auth)
├─ sandbox/                # Playwright sandbox, dataset generation, conversion, diagnostics, L3 training
├─ supabase/               # Optional Postgres schema for auth-linked history/settings sync
├─ behavioral_transformer.py
├─ requirements.txt
├─ package.json
├─ dataset_phishing.csv
├─ Copy_of_PP1.ipynb
└─ readme.md
```

### Folder Notes

- `api/`
  - `main.py` exposes the local API
  - `rf_hybrid_minilm.pkl`, `scaler_hybrid.pkl`, and `behavior_transformer.pt` are runtime artifacts
  - `extraction.py` and `extract_features.py` handle URL feature extraction
- `extension/`
  - `popup.*`, `dashboard.*`, `history.*`, `settings.*`, `warning/*`, and `background.js` implement the extension flow
  - `lib/` contains storage, auth, controls, history, settings, explainability, and Supabase helpers
- `sandbox/`
  - `run_dataset.py`, `json_to_csv.py`, `train_model.py`, `analyze_dataset.py`, `sanity_check.py`, and `calibrate_thresholds.py` support L3 dataset generation and model training
- `supabase/schema.sql`
  - Optional schema for profiles, scan history, logs, user settings, allowlist/blocklist, and weekly summaries

## Requirements

### Prerequisites

- Python 3.12.x
- Node.js + npm
- Google Chrome
- Local Python environment with FastAPI/ML dependencies
- Playwright Chromium browser installed
- Supabase project only if cloud sync/auth is enabled

### Python / Backend Dependencies

Install from the repository root:

```powershell
pip install -r requirements.txt
```

The repository also contains a narrower sandbox dependency list in `sandbox/requirement.txt`.

### Playwright Browser Setup

After installing Python dependencies, install the required browser:

```powershell
python -m playwright install chromium
```

### Supabase (Optional)

Supabase is optional. The extension works with local storage only, but auth/history sync requires:

- a Supabase project
- Auth enabled
- the SQL schema in `supabase/schema.sql`
- project URL and anon key configured locally

## Backend Setup

From the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m playwright install chromium
uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
```

Backend base URL:

```text
http://localhost:8000
```

Full extension functionality depends on this backend being available locally.

## Extension Setup

Install Node dependencies and build the bundled Supabase browser client:

```powershell
npm install
npm run build
```

Then load the extension:

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `extension/` folder

### Config Notes

- The extension currently points to the local backend through `extension/lib/constants.js`
- The manifest already includes `http://localhost:8000/*` in `host_permissions`
- If you change the backend host or port, update `FAST_API_BASE` in `extension/lib/constants.js`

## Supabase Setup (Optional)

Do **not** commit secrets or environment-specific credentials.

If you want auth and sync:

1. Create a Supabase project
2. Apply the schema in:

```text
supabase/schema.sql
```

3. Configure placeholders for:

```text
SUPABASE_URL
SUPABASE_ANON_KEY
```

4. Update local extension config accordingly

The current extension config is stored in `extension/lib/config.js`. Replace any project-specific values with your own local placeholders before sharing or deploying. Auth/history sync is optional; the extension can run in local-only mode.

## How to Use

1. Start the FastAPI backend locally.
2. Load the extension in Chrome.
3. Open a website.
4. Click the extension popup to view the L1+L2 fast scan result.
5. Trigger a deep scan when you want sandbox-based verification.
6. Open the dashboard/history page to review saved scan records.
7. Use settings to change scan mode, threshold, security mode, and blocking behavior.
8. If a page crosses the configured risk/block threshold, the warning page flow can intercept navigation.

## API Endpoints

Verified from `api/main.py`:

- `GET /`
  - Health/info message
- `POST /predict`
  - Fast L1+L2 phishing scan
- `POST /deep_scan`
  - L3 sandbox-assisted deep scan
- `POST /explain_shap`
  - Returns SHAP graph data and top contributing features
- `GET /sandbox_shot`
  - Returns the latest sandbox screenshot image if available

## ML Pipeline Summary

### L1+L2 Fast Scan

- MiniLM sentence embeddings from `SentenceTransformer`
- Handcrafted URL feature extraction from the backend extraction logic
- Scaled numeric features combined with embeddings
- Random Forest classification
- Rule-based score overlay for explicit suspicious-pattern reasoning

### L3 Sandbox Behavioral Model

- Playwright-based sandbox execution collects runtime request/redirect/resource behavior
- Behavioral features are converted into a structured dataset
- The deep-scan model is served through `behavior_transformer.pt`
- Backend inference uses `BehavioralPredictor`

### SHAP Explainability

- SHAP is applied to the Random Forest fast-scan path
- The backend generates feature contribution plots and ranked feature explanations for detailed inspection

## Dataset and Training Pipeline

The repository includes an L3 behavioral training flow:

- `sandbox/extract_urls.py` — prepares labeled URLs
- `sandbox/run_dataset.py` — executes large-scale sandbox scans
- `sandbox/json_to_csv.py` — converts raw JSON scan output into `dataset.csv`
- `sandbox/analyze_dataset.py` — diagnostics and quality review
- `sandbox/sanity_check.py` — API/runtime sanity testing
- `sandbox/calibrate_thresholds.py` — threshold evaluation support
- `sandbox/train_model.py` — trains the behavioral transformer and RF baseline artifacts

There are also notebook/data artifacts at the root, including `Copy_of_PP1.ipynb`, `dataset_phishing.csv`, and related experiment outputs.

## Notes

- The backend must be running locally for prediction, deep scan, SHAP generation, and sandbox screenshot access.
- Some websites may block automation or return challenge pages during deep scan; the backend surfaces these as inaccessible sandbox states instead of forcing a misleading classification.
- Before publishing or sharing the project, rotate or remove any environment-specific auth values and keep only placeholders in config examples.
