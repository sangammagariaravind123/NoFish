import { DEEP_SCAN_URL, PREDICT_URL, STORAGE_KEYS } from "./lib/constants.js";
import { restoreSessionContext } from "./lib/auth.js";
import { getControlState, resolveControlDecision } from "./lib/controls.js";
import { getKnownPhishingMatch, persistScanRecord } from "./lib/history.js";
import { ensureLocalSettings, getSettings } from "./lib/settings-store.js";
import { setLocal } from "./lib/storage.js";

const cache = new Map();

function updateIcon(risk) {
  let iconPath = "icons/safe.png";
  if (risk === "Phishing") iconPath = "icons/danger.png";
  else if (risk === "Suspicious") iconPath = "icons/warning.png";
  chrome.action.setIcon({ path: iconPath });
}

function isSkippableUrl(url) {
  return !url ||
    url.startsWith("chrome://") ||
    url.startsWith("about:") ||
    url.startsWith("edge://") ||
    url.startsWith("chrome-extension://");
}

function buildWarningUrl(url, trust, reason) {
  return chrome.runtime.getURL("warning/warning.html") +
    `?url=${encodeURIComponent(url)}&trust=${encodeURIComponent(String(trust ?? 0))}&reason=${encodeURIComponent(reason || "")}`;
}

function getScanMode(settings) {
  return settings.scanMode === "deep" ? "deep" : "fast";
}

function getCacheKey(url, scanMode) {
  return `${scanMode}:${url}`;
}

function getClassification(result, scanMode) {
  return scanMode === "deep" ? result.final_risk : result.risk;
}

function getTrustScore(result, scanMode) {
  return scanMode === "deep" ? result.final_trust_index : result.trust_index;
}

function summarizeDeepResult(result) {
  return {
    risk: result.final_risk,
    trust_index: result.final_trust_index,
    ml_prob: result.l1l2?.ml_prob ?? 0,
    rule_score: result.l1l2?.rule_score ?? 0,
    triggered_rules: result.l1l2?.triggered_rules ?? []
  };
}

function buildPopupResultRecord(url, result, scanMode, source = "scan") {
  return {
    url,
    scanMode,
    source,
    timestamp: Date.now(),
    result
  };
}

async function requestScan(url, settings) {
  const scanMode = getScanMode(settings);
  const cacheKey = getCacheKey(url, scanMode);
  if (cache.has(cacheKey)) {
    return { scanMode, result: cache.get(cacheKey) };
  }

  const endpoint = scanMode === "deep" ? DEEP_SCAN_URL : PREDICT_URL;
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  });

  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }

  const result = await response.json();
  cache.set(cacheKey, result);

  if (cache.size > 100) {
    const oldestKey = cache.keys().next().value;
    cache.delete(oldestKey);
  }

  return { scanMode, result };
}

async function storeResultForPopup(url, scanMode, result) {
  const payload = {};

  if (scanMode === "deep") {
    payload[STORAGE_KEYS.deepScanResult] = {
      url,
      result,
      timestamp: Date.now()
    };
  } else {
    payload[STORAGE_KEYS.lastResult] = buildPopupResultRecord(url, result, scanMode, "scan");
  }

  await setLocal(payload);
}

async function storeOverrideResult(url, kind, reason) {
  if (kind === "allow") {
    await setLocal({
      [STORAGE_KEYS.lastResult]: buildPopupResultRecord(url, {
        risk: "Safe",
        trust_index: 1,
        ml_prob: 0,
        rule_score: 0,
        triggered_rules: [reason]
      }, "fast", "override")
    });
    updateIcon("Safe");
    return;
  }

  await setLocal({
    [STORAGE_KEYS.lastResult]: buildPopupResultRecord(url, {
      risk: "Phishing",
      trust_index: 0,
      ml_prob: 1,
      rule_score: 1,
      triggered_rules: [reason]
    }, "fast", "override")
  });
  updateIcon("Phishing");
}

async function shouldBlock(result, scanMode, settings) {
  const classification = getClassification(result, scanMode);
  const trustScore = getTrustScore(result, scanMode);
  const riskPercent = (1 - (trustScore ?? 0)) * 100;

  if (classification === "Phishing") {
    return settings.autoBlockPhishing || settings.autoBlockEnabled;
  }

  if (!settings.autoBlockEnabled) return false;
  return riskPercent >= settings.riskThreshold;
}

async function resolveKnownPhishingDecision(url, settings) {
  if (!settings.autoBlockPhishing) return null;

  const knownPhishing = await getKnownPhishingMatch(url);
  if (!knownPhishing) return null;

  const label = knownPhishing.type === "domain" ? "known phishing domain" : "known phishing URL";
  return {
    decision: "block",
    reason: `Matched ${label} from scan history`,
    source: "history",
    match: knownPhishing.match
  };
}

async function processNavigation(details) {
  const url = details.url;
  if (details.frameId !== 0 || isSkippableUrl(url)) {
    return;
  }

  const settings = await getSettings();
  const decision = await resolveControlDecision(url);

  if (decision.decision === "allow") {
    await storeOverrideResult(url, "allow", decision.reason);
    return;
  }

  if (decision.decision === "block") {
    await storeOverrideResult(url, "block", decision.reason);
    chrome.tabs.update(details.tabId, { url: buildWarningUrl(url, 0, decision.reason) });
    return;
  }

  const historyDecision = await resolveKnownPhishingDecision(url, settings);
  if (historyDecision?.decision === "block") {
    await storeOverrideResult(url, "block", historyDecision.reason);
    chrome.tabs.update(details.tabId, { url: buildWarningUrl(url, 0, historyDecision.reason) });
    return;
  }

  chrome.action.setIcon({ path: "icons/checking.png" });

  try {
    const { scanMode, result } = await requestScan(url, settings);
    await storeResultForPopup(url, scanMode, result);
    updateIcon(getClassification(result, scanMode));
    await persistScanRecord({
      url,
      result,
      scanType: scanMode === "deep" ? "deep" : "predict",
      source: "navigation"
    }).catch((error) => console.warn("History persistence failed:", error));

    if (await shouldBlock(result, scanMode, settings)) {
      const classification = getClassification(result, scanMode);
      const trustScore = getTrustScore(result, scanMode);
      const reason = scanMode === "deep"
        ? (result.l1l2?.triggered_rules || []).join(", ") || `${classification} threshold exceeded`
        : (result.triggered_rules || []).join(", ") || `${classification} threshold exceeded`;

      chrome.tabs.update(details.tabId, {
        url: buildWarningUrl(url, trustScore, reason)
      });
    }
  } catch (error) {
    console.error("API call failed:", error);
    await setLocal({
      [STORAGE_KEYS.lastResult]: buildPopupResultRecord(url, {
        risk: "Unknown",
        trust_index: 0.5,
        triggered_rules: ["Scan unavailable"]
      }, "fast", "error")
    });
    updateIcon("Unknown");
  }
}

async function initializeExtensionState() {
  await restoreSessionContext().catch((error) => console.warn("Session restore skipped:", error));
  await ensureLocalSettings();
  await getControlState();
}

chrome.runtime.onInstalled.addListener(() => {
  initializeExtensionState().catch((error) => console.error("Initialization error:", error));
});

chrome.runtime.onStartup.addListener(() => {
  initializeExtensionState().catch((error) => console.error("Startup error:", error));
});

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  processNavigation(details).catch((error) => console.error("Navigation scan failed:", error));
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local") return;
  if (!changes[STORAGE_KEYS.supabaseSession]) return;

  initializeExtensionState().catch((error) => console.error("Auth state refresh failed:", error));
});
