export const FAST_API_BASE = "http://localhost:8000";
export const PREDICT_URL = `${FAST_API_BASE}/predict`;
export const DEEP_SCAN_URL = `${FAST_API_BASE}/deep_scan`;
export const TEMP_ALLOW_MINUTES = 10;
export const MAX_LOCAL_HISTORY = 250;

export const STORAGE_KEYS = {
  authCache: "authSessionCache",
  supabaseSession: "phishguard.supabase.session",
  lastResult: "lastResult",
  deepScanResult: "deepScanResult",
  popupState: "popupState",
  settings: "userSettingsCache",
  uiState: "uiPreferences",
  controls: "controlRulesCache",
  recentScans: "recentScansCache",
  analysisLogs: "analysisLogsCache",
  warningEvents: "warningEventsCache"
};

export const DEFAULT_SETTINGS = {
  autoBlockEnabled: true,
  autoBlockPhishing: true,
  riskThreshold: 60,
  scanMode: "fast",
  securityMode: "balanced"
};

export const DEFAULT_UI_STATE = {
  explainMode: "simple"
};

export const SECURITY_MODE_PRESETS = {
  strict: {
    autoBlockEnabled: true,
    autoBlockPhishing: true,
    riskThreshold: 40,
    scanMode: "deep"
  },
  balanced: {
    autoBlockEnabled: true,
    autoBlockPhishing: true,
    riskThreshold: 60,
    scanMode: "fast"
  },
  relaxed: {
    autoBlockEnabled: false,
    autoBlockPhishing: false,
    riskThreshold: 80,
    scanMode: "fast"
  }
};

export const DEFAULT_CONTROL_RULES = {
  allowRules: [],
  blockRules: [],
  temporaryAllows: []
};

export const RISK_ORDER = ["Safe", "Suspicious", "Phishing"];
