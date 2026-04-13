import { signInWithEmail, signOutUser, signUpWithEmail, getCachedAuth, registerAuthStateListener, restoreSessionContext } from "./lib/auth.js";
import { buildExplanation, highlightSuspiciousUrl } from "./lib/explain.js";
import { persistScanRecord } from "./lib/history.js";
import { getUiState, setUiState } from "./lib/settings-store.js";
import { getLocal, setLocal } from "./lib/storage.js";
import { classificationClass, formatPercent, openExtensionPage, safeText } from "./lib/ui-utils.js";

const DEEP_SCAN_EXPIRY = 5 * 60 * 1000;
const SANDBOX_SHOT_URL = "http://localhost:8000/sandbox_shot";
let authFormMode = null;

function normalizePopupResultRecord(record) {
  if (!record) return null;

  if (record.result && record.url) {
    return record;
  }

  return {
    url: null,
    scanMode: "fast",
    source: "legacy",
    timestamp: 0,
    result: record
  };
}

function shouldUseDeepResult(currentUrl, deepScanRecord, lastResultRecord) {
  if (!currentUrl || !deepScanRecord || deepScanRecord.url !== currentUrl) {
    return false;
  }

  if (Date.now() - deepScanRecord.timestamp >= DEEP_SCAN_EXPIRY) {
    return false;
  }

  if (!lastResultRecord || lastResultRecord.url !== currentUrl) {
    return true;
  }

  return Number(deepScanRecord.timestamp || 0) >= Number(lastResultRecord.timestamp || 0);
}

function formatList(items, emptyText = "None") {
  if (!items || !items.length) return emptyText;
  return items.map((item) => `• ${safeText(item)}`).join("<br>");
}

function buildRequestList(requests) {
  if (!requests || !requests.length) {
    return `
      <button id="toggleRequestsBtn" class="nested-btn">Show All Requests</button>
      <div id="allRequestsContainer" class="request-list">
        <div class="small-text">No requests captured.</div>
      </div>
    `;
  }

  const listItems = requests.map((req) => `<li>${safeText(req)}</li>`).join("");
  return `
    <button id="toggleRequestsBtn" class="nested-btn">Show All Requests</button>
    <ol id="allRequestsContainer" class="request-list">${listItems}</ol>
  `;
}

function attachNestedRequestToggle() {
  const toggleBtn = document.getElementById("toggleRequestsBtn");
  const reqBox = document.getElementById("allRequestsContainer");
  if (!toggleBtn || !reqBox) return;

  toggleBtn.onclick = () => {
    const visible = reqBox.style.display === "block";
    reqBox.style.display = visible ? "none" : "block";
    toggleBtn.textContent = visible ? "Show All Requests" : "Hide All Requests";
  };
}

async function renderAuthState() {
  const auth = await getCachedAuth();
  const accountCard = document.getElementById("accountState");
  const authForm = document.getElementById("authForm");
  const authActions = document.getElementById("authActions");

  if (auth?.email) {
    setAuthFormMode(null);
    accountCard.innerHTML = `
      <div class="auth-label">Signed in as</div>
      <div class="auth-email">${safeText(auth.email)}</div>
      <div class="small-text">${safeText(auth.provider || "email")} account</div>
    `;
    authForm.style.display = "none";
    authActions.innerHTML = `<button id="logoutBtn" class="secondary-btn">Log Out</button>`;
    document.getElementById("logoutBtn").addEventListener("click", async () => {
      await signOutUser();
      await renderAuthState();
      setAuthMessage("Signed out.");
    });
    return;
  }

  setAuthFormMode(null);
  accountCard.innerHTML = `
    <div class="auth-label">Local mode</div>
    <div class="small-text">Sign in to sync history, settings, and control lists across devices.</div>
  `;
  authForm.style.display = "none";
  authActions.innerHTML = `
    <button id="showLoginBtn" class="secondary-btn">Login</button>
    <button id="showSignupBtn">Sign Up</button>
    <button id="googleLoginBtn" class="ghost-btn">Continue with Google</button>
  `;
  document.getElementById("showLoginBtn").addEventListener("click", () => setAuthFormMode("login"));
  document.getElementById("showSignupBtn").addEventListener("click", () => setAuthFormMode("signup"));
  document.getElementById("googleLoginBtn").addEventListener("click", handleGoogleLogin);
}

function setAuthFormMode(mode) {
  authFormMode = mode;
  const form = document.getElementById("authForm");
  const title = document.getElementById("authFormTitle");
  const displayNameInput = document.getElementById("displayNameInput");
  const loginBtn = document.getElementById("loginBtn");
  const signupBtn = document.getElementById("signupBtn");
  const cancelBtn = document.getElementById("cancelAuthBtn");

  if (!mode) {
    form.style.display = "none";
    title.textContent = "";
    return;
  }

  form.style.display = "flex";
  title.textContent = mode === "signup" ? "Create your account" : "Log in to your account";
  displayNameInput.style.display = mode === "signup" ? "block" : "none";
  loginBtn.style.display = mode === "login" ? "block" : "none";
  signupBtn.style.display = mode === "signup" ? "block" : "none";
  cancelBtn.style.display = "block";
}

function setAuthMessage(message, isError = false) {
  const box = document.getElementById("authMessage");
  box.textContent = message || "";
  box.className = isError ? "message error" : "message";
}

async function handleEmailAuth(mode) {
  const email = document.getElementById("emailInput").value.trim();
  const password = document.getElementById("passwordInput").value.trim();
  const displayName = document.getElementById("displayNameInput").value.trim();

  if (!email || !password) {
    setAuthMessage("Email and password are required.", true);
    return;
  }

  try {
    if (mode === "signup") {
      await signUpWithEmail(email, password, displayName);
      setAuthMessage("Account created successfully.");
    } else {
      await signInWithEmail(email, password);
      setAuthMessage("Logged in successfully.");
    }
    setAuthFormMode(null);
    await renderAuthState();
  } catch (error) {
    setAuthMessage(error.message || "Authentication failed.", true);
  }
}

async function handleGoogleLogin() {
  try {
    await openExtensionPage("dashboard.html?auth=google");
    setAuthMessage("Opening Google sign-in in the dashboard tab...");
  } catch (error) {
    setAuthMessage(error.message || "Google sign-in failed.", true);
  }
}

function buildSimpleExplainSection(result, isDeepScan) {
  const explanation = buildExplanation(result, isDeepScan);
  const url = isDeepScan ? result.scanned_url : result.url;
  return `
    <div class="detail-block">
      <strong>Why this may be risky</strong><br>
      ${explanation.why.map((item) => `• ${safeText(item)}`).join("<br>")}
    </div>
    <div class="detail-block">
      <strong>What might happen if you proceed</strong><br>
      ${explanation.impact.map((item) => `• ${safeText(item)}`).join("<br>")}
    </div>
    ${url ? `
      <div class="detail-block">
        <strong>Suspicious URL parts</strong><br>
        <span class="url-line">${highlightSuspiciousUrl(url)}</span>
      </div>` : ""}
  `;
}

async function renderExplanationBox(result, isDeepScan) {
  const explanationBox = document.getElementById("explanationBox");
  const uiState = await getUiState();
  const mode = uiState.explainMode;
  const modeBtn = document.getElementById("explainModeBtn");
  modeBtn.textContent = `Mode: ${mode === "simple" ? "Simple" : "Technical"}`;

  if (!isDeepScan) {
    explanationBox.innerHTML = buildSimpleExplainSection(result, false);
    return;
  }

  const raw = result.sandbox?.raw_output || {};
  const inaccessible = raw.sandbox_accessible === false || result.final_risk === "Unknown";
  const downloadList = (raw.download_attempts || []).map(
    (item) => `${item.suggested_filename || "unknown"} (${item.url || "no url"})`
  );

  if (inaccessible) {
    const blockedReason = raw.sandbox_blocked_reason || result.sandbox?.blocked_reason || "Sandbox can't access this site.";

    explanationBox.innerHTML = `
      <div class="detail-block">
        <strong>Sandbox status</strong><br>
        • ${safeText(blockedReason)}<br>
        • The deep scan could not access the real site content, so no L3 phishing verdict was produced.
      </div>
      <div class="detail-block">
        <strong>L1+L2 quick scan</strong><br>
        • Risk: ${safeText(result.l1l2?.risk || "Unknown")}<br>
        • Trust Index: ${formatPercent(result.l1l2?.trust_index ?? null)}<br>
        • ML probability: ${formatPercent(result.l1l2?.ml_prob ?? null)}<br>
        • Rule score: ${formatPercent(result.l1l2?.rule_score ?? null)}
      </div>
      <div class="detail-block">
        <strong>Observed page details</strong><br>
        • Final URL: ${safeText(raw.final_url || "N/A")}<br>
        • Page title: ${safeText(raw.page_title || "N/A")}<br>
        • HTML length: ${raw.html_length ?? "N/A"}<br>
        • HTTP status: ${raw.main_response_status ?? "N/A"}<br>
        • Total requests: ${raw.total_requests ?? "N/A"}
      </div>
    `;
    return;
  }

  if (mode === "simple") {
    explanationBox.innerHTML = `
      ${buildSimpleExplainSection(result, true)}
      <div class="detail-block">
        <strong>Decision breakdown</strong><br>
        • ML score: ${formatPercent(result.l1l2?.ml_prob ?? null)}<br>
        • Rule score: ${formatPercent(result.l1l2?.rule_score ?? null)}<br>
        • Sandbox score: ${formatPercent(result.sandbox?.behavioral_prob ?? null)}
      </div>
    `;
    return;
  }

  explanationBox.innerHTML = `
    ${buildSimpleExplainSection(result, true)}
    <strong>Sandbox Output</strong><br><br>
    <strong>Original URL:</strong>
    <span class="url-line">${safeText(raw.url || "N/A")}</span>
    <strong>Final URL:</strong>
    <span class="url-line">${safeText(raw.final_url || "N/A")}</span>
    <strong>Behavior Summary</strong><br>
    • Total requests: ${raw.total_requests ?? "N/A"}<br>
    • External domain count: ${raw.external_domain_count ?? "N/A"}<br>
    • Redirect count: ${raw.redirect_count ?? "N/A"}<br>
    • JavaScript requests: ${raw.js_requests ?? "N/A"}<br>
    • Download attempts: ${(raw.download_attempts || []).length}<br><br>
    <strong>Advanced Signals</strong><br>
    • Final URL differs: ${raw.final_url_differs ?? "N/A"}<br>
    • Unique request domains: ${raw.unique_request_domains ?? "N/A"}<br>
    • External request ratio: ${raw.external_request_ratio ?? "N/A"}<br>
    • Error flag: ${raw.error_flag ?? "N/A"}<br>
    • Timeout flag: ${raw.timeout_flag ?? "N/A"}<br><br>
    <strong>External Domains Contacted</strong><br>
    ${formatList(raw.external_domains || [])}<br><br>
    <strong>Download Attempt Details</strong><br>
    ${formatList(downloadList, "None")}<br><br>
    ${buildRequestList(raw.all_requests || [])}
  `;
}

function showSandboxScreenshot() {
  const resultBox = document.getElementById("result");
  const screenshotView = document.getElementById("sandboxScreenshotView");
  const screenshotImage = document.getElementById("sandboxScreenshotImage");
  const deepScanBtn = document.getElementById("deepScanBtn");
  const loadingDiv = document.getElementById("loading");
  const explanationBox = document.getElementById("explanationBox");
  const actionRow = document.getElementById("resultActionsRow");

  screenshotImage.src = `${SANDBOX_SHOT_URL}?t=${Date.now()}`;
  resultBox.style.display = "none";
  screenshotView.classList.add("active");
  deepScanBtn.style.display = "none";
  loadingDiv.style.display = "none";
  explanationBox.style.display = "none";
  actionRow.style.display = "none";
}

function hideSandboxScreenshot() {
  const resultBox = document.getElementById("result");
  const screenshotView = document.getElementById("sandboxScreenshotView");
  const screenshotImage = document.getElementById("sandboxScreenshotImage");
  const deepScanBtn = document.getElementById("deepScanBtn");
  const actionRow = document.getElementById("resultActionsRow");

  screenshotView.classList.remove("active");
  screenshotImage.removeAttribute("src");
  resultBox.style.display = "";
  deepScanBtn.style.display = "";
  actionRow.style.display = "";
}

function openFullSandboxScreenshot() {
  window.open(`${SANDBOX_SHOT_URL}?t=${Date.now()}`, "_blank", "noopener,noreferrer");
}

async function displayResult(result, isDeepScan = false) {
  hideSandboxScreenshot();
  const container = document.getElementById("result");
  const whyBtn = document.getElementById("whyBtn");
  const explanationBox = document.getElementById("explanationBox");

  if (!result) {
    container.innerHTML = "<p>No recent scan.</p>";
    whyBtn.style.display = "none";
    explanationBox.style.display = "none";
    return;
  }

  if (isDeepScan) {
    const risk = result.final_risk || "Unknown";
    const trustIndex = result.final_trust_index;
    const l1l2 = result.l1l2 || {};
    const inaccessible = result.sandbox?.raw_output?.sandbox_accessible === false || risk === "Unknown";
    const blockedReason = result.sandbox?.raw_output?.sandbox_blocked_reason || result.sandbox?.blocked_reason;

    container.innerHTML = `
      <div class="result-toolbar"><button id="showSandboxShotBtn" class="ghost-btn compact-btn">Show Scanned URL</button></div>
      <div class="risk ${classificationClass(risk)}">Risk: <strong>${safeText(risk)}</strong></div>
      <div class="trust">Trust Index: ${trustIndex == null ? "N/A" : `${(trustIndex * 100).toFixed(1)}%`}</div>
      ${inaccessible ? `<div class="detail-block compact"><strong>Sandbox can't access this site.</strong>${blockedReason ? `<br>${safeText(blockedReason)}` : ""}</div>` : ""}
      <div class="rules"><strong>Rules triggered:</strong> ${l1l2.triggered_rules?.length ? safeText(l1l2.triggered_rules.join(", ")) : "None"}</div>
      <hr>
      <div><small>L1+L2 risk: ${safeText(l1l2.risk || "Unknown")}</small></div>
      <div><small>ML probability: ${((l1l2.ml_prob ?? 0) * 100).toFixed(1)}%</small></div>
      <div><small>Rule score: ${((l1l2.rule_score ?? 0) * 100).toFixed(1)}%</small></div>
      <div><small>Sandbox score: ${result.sandbox?.behavioral_prob == null ? "N/A" : `${(result.sandbox.behavioral_prob * 100).toFixed(1)}%`}</small></div>
      <div class="small-text">Scanned URL: ${safeText(result.scanned_url || "N/A")}</div>
    `;

    whyBtn.style.display = "block";
    whyBtn.textContent = "Show Why";
    explanationBox.style.display = "none";
    document.getElementById("showSandboxShotBtn")?.addEventListener("click", showSandboxScreenshot);
    await renderExplanationBox(result, true);
    return;
  }

  container.innerHTML = `
    <div class="risk ${classificationClass(result.risk)}">Risk: <strong>${safeText(result.risk || "Unknown")}</strong></div>
    <div class="trust">Trust Index: ${((result.trust_index ?? 0) * 100).toFixed(1)}%</div>
    <div class="rules"><strong>Rules triggered:</strong> ${result.triggered_rules?.length ? safeText(result.triggered_rules.join(", ")) : "None"}</div>
    <hr>
    <div><small>ML probability: ${((result.ml_prob ?? 0) * 100).toFixed(1)}%</small></div>
    <div><small>Rule score: ${((result.rule_score ?? 0) * 100).toFixed(1)}%</small></div>
    <div class="detail-block compact">${buildSimpleExplainSection(result, false)}</div>
  `;
  whyBtn.style.display = "none";
  explanationBox.style.display = "none";
}

function toggleExplanation() {
  const box = document.getElementById("explanationBox");
  const btn = document.getElementById("whyBtn");
  const visible = box.style.display === "block";
  box.style.display = visible ? "none" : "block";
  btn.textContent = visible ? "Show Why" : "Hide Why";
  attachNestedRequestToggle();
}

async function toggleExplainMode() {
  const currentState = await getUiState();
  const nextMode = currentState.explainMode === "simple" ? "technical" : "simple";
  await setUiState({ explainMode: nextMode });

  const { deepScanResult } = await getLocal(["deepScanResult"]);
  if (deepScanResult?.result) {
    await renderExplanationBox(deepScanResult.result, true);
  }
}

async function getCurrentTabUrl() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0]?.url;
}

async function getUrlForDeepScan() {
  const currentUrl = await getCurrentTabUrl();
  if (!currentUrl) return null;

  if (currentUrl.includes("/warning/warning.html")) {
    try {
      const parsed = new URL(currentUrl);
      const originalUrl = parsed.searchParams.get("url");
      return originalUrl || currentUrl;
    } catch (error) {
      return currentUrl;
    }
  }

  return currentUrl;
}

async function runDeepScan() {
  const loadingDiv = document.getElementById("loading");
  const btn = document.getElementById("deepScanBtn");
  const explanationBox = document.getElementById("explanationBox");
  const whyBtn = document.getElementById("whyBtn");

  loadingDiv.style.display = "block";
  btn.disabled = true;
  explanationBox.style.display = "none";
  whyBtn.style.display = "none";

  const url = await getUrlForDeepScan();
  if (!url) {
    loadingDiv.style.display = "none";
    btn.disabled = false;
    document.getElementById("result").innerHTML = "<p>Could not get current tab URL.</p>";
    return;
  }

  try {
    const response = await fetch("http://localhost:8000/deep_scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const deepResult = await response.json();

    const deepScanStore = {
      url,
      result: deepResult,
      timestamp: Date.now()
    };

    await setLocal({
      deepScanResult: deepScanStore
    });

    await persistScanRecord({
      url,
      result: deepResult,
      scanType: "deep",
      source: "popup"
    }).catch((error) => console.warn("Deep scan persistence failed:", error));

    await displayResult(deepResult, true);
  } catch (error) {
    console.error("Deep scan error:", error);
    document.getElementById("result").innerHTML = `<p>Deep scan failed.<br>${safeText(error.message)}</p>`;
    document.getElementById("whyBtn").style.display = "none";
  } finally {
    loadingDiv.style.display = "none";
    btn.disabled = false;
  }
}

async function initializePopup() {
  await restoreSessionContext().catch((error) => console.warn("Popup session restore skipped:", error));
  await renderAuthState();

  const currentUrl = await getUrlForDeepScan();
  const data = await getLocal(["deepScanResult", "lastResult"]);
  const lastResultRecord = normalizePopupResultRecord(data.lastResult);

  if (!currentUrl) {
    document.getElementById("result").innerHTML = "<p>Unable to get current tab URL.</p>";
  } else if (shouldUseDeepResult(currentUrl, data.deepScanResult, lastResultRecord)) {
    await displayResult(data.deepScanResult.result, true);
  } else if (
    lastResultRecord &&
    lastResultRecord.url === currentUrl &&
    lastResultRecord.scanMode !== "deep" &&
    lastResultRecord.result
  ) {
    await displayResult(lastResultRecord.result, false);
  } else {
    document.getElementById("result").innerHTML = "<p>No recent scan.</p>";
  }

  document.getElementById("deepScanBtn").addEventListener("click", runDeepScan);
  document.getElementById("whyBtn").addEventListener("click", toggleExplanation);
  document.getElementById("explainModeBtn").addEventListener("click", toggleExplainMode);
  document.getElementById("backToResultBtn").addEventListener("click", hideSandboxScreenshot);
  document.getElementById("openFullScreenshotBtn").addEventListener("click", openFullSandboxScreenshot);
  document.getElementById("cancelAuthBtn").addEventListener("click", () => setAuthFormMode(null));
  document.getElementById("loginBtn").addEventListener("click", () => handleEmailAuth("login"));
  document.getElementById("signupBtn").addEventListener("click", () => handleEmailAuth("signup"));
  document.getElementById("dashboardBtn").addEventListener("click", () => openExtensionPage("dashboard.html"));
  document.getElementById("settingsBtn").addEventListener("click", () => openExtensionPage("settings.html"));

  registerAuthStateListener(() => {
    renderAuthState().catch((error) => setAuthMessage(error.message, true));
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initializePopup().catch((error) => {
    console.error("Popup init failed:", error);
    setAuthMessage(error.message || "Failed to initialize popup.", true);
  });
});
