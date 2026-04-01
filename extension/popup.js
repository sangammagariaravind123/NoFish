const DEEP_SCAN_EXPIRY = 5 * 60 * 1000; // 5 minutes

function safeText(value) {
  if (value === null || value === undefined) return "N/A";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatList(items, emptyText = "None") {
  if (!items || !items.length) return emptyText;
  return items.map(item => `• ${safeText(item)}`).join("<br>");
}

function buildRequestList(requests) {
  if (!requests || !requests.length) {
    return `
      <button id="toggleRequestsBtn" class="nested-btn">📄 Show All Requests</button>
      <div id="allRequestsContainer" class="request-list">
        <div class="small-text">No requests captured.</div>
      </div>
    `;
  }

  const listItems = requests.map(req => `<li>${safeText(req)}</li>`).join("");

  return `
    <button id="toggleRequestsBtn" class="nested-btn">📄 Show All Requests</button>
    <ol id="allRequestsContainer" class="request-list">
      ${listItems}
    </ol>
  `;
}

function attachNestedRequestToggle() {
  const toggleBtn = document.getElementById("toggleRequestsBtn");
  const reqBox = document.getElementById("allRequestsContainer");

  if (!toggleBtn || !reqBox) return;

  toggleBtn.onclick = () => {
    if (reqBox.style.display === "none" || reqBox.style.display === "") {
      reqBox.style.display = "block";
      toggleBtn.textContent = "📄 Hide All Requests";
    } else {
      reqBox.style.display = "none";
      toggleBtn.textContent = "📄 Show All Requests";
    }
  };
}

// Display either normal L1+L2 result or deep scan result
function displayResult(result, isDeepScan = false) {
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
    const trustIndex = result.final_trust_index ?? 0;
    const riskClass = risk.toLowerCase();

    const l1l2 = result.l1l2 || {};
    const mlProb = l1l2.ml_prob ?? 0;
    const ruleScore = l1l2.rule_score ?? 0;
    const triggeredRules = l1l2.triggered_rules || [];

    const sandboxProb = result.sandbox?.behavioral_prob;
    const raw = result.sandbox?.raw_output || {};

    container.innerHTML = `
      <div class="risk ${riskClass}">Risk: <strong>${safeText(risk)}</strong></div>
      <div class="trust">Trust Index: ${(trustIndex * 100).toFixed(1)}%</div>
      <div class="rules"><strong>Rules triggered:</strong> ${triggeredRules.length ? safeText(triggeredRules.join(", ")) : "None"}</div>
      <hr>
      <div><small>ML probability: ${(mlProb * 100).toFixed(1)}%</small></div>
      <div><small>Rule score: ${(ruleScore * 100).toFixed(1)}%</small></div>
      <div><small>Sandbox behavioral probability: ${
        sandboxProb !== undefined ? (sandboxProb * 100).toFixed(1) : "N/A"
      }%</small></div>
      <hr>
      <div class="rules"><strong>Scanned URL:</strong></div>
      <span class="url-line">${safeText(result.scanned_url || "N/A")}</span>
      <div class="rules"><strong>Final URL:</strong></div>
      <span class="url-line">${safeText(raw.final_url || "N/A")}</span>
    `;

    const downloadList = (raw.download_attempts || []).map(
      d => `${d.suggested_filename || "unknown"} (${d.url || "no url"})`
    );

    explanationBox.innerHTML = `
      <strong>🔬 Sandbox Output</strong><br><br>

      <strong>Original URL:</strong>
      <span class="url-line">${safeText(raw.url || "N/A")}</span>

      <strong>Final URL:</strong>
      <span class="url-line">${safeText(raw.final_url || "N/A")}</span>

      <strong>Behavior Summary</strong><br>
      • Total requests: ${raw.total_requests ?? "N/A"}<br>
      • External domain count: ${raw.external_domain_count ?? "N/A"}<br>
      • Redirect count: ${raw.redirect_count ?? "N/A"}<br>
      • JavaScript requests: ${raw.js_requests ?? "N/A"}<br>
      • IP-based requests: ${raw.ip_based_requests ?? "N/A"}<br>
      • Suspicious TLD count: ${raw.suspicious_tld_count ?? "N/A"}<br>
      • Download attempts: ${(raw.download_attempts || []).length}<br><br>

      <strong>Advanced Signals</strong><br>
      • Final URL differs: ${raw.final_url_differs ?? "N/A"}<br>
      • Unique request domains: ${raw.unique_request_domains ?? "N/A"}<br>
      • Domain diversity ratio: ${raw.unique_request_domain_ratio ?? "N/A"}<br>
      • Script domain count: ${raw.script_domain_count ?? "N/A"}<br>
      • External request ratio: ${raw.external_request_ratio ?? "N/A"}<br>
      • Error flag: ${raw.error_flag ?? "N/A"}<br>
      • Timeout flag: ${raw.timeout_flag ?? "N/A"}<br><br>

      <strong>Request Type Breakdown</strong><br>
      • Document: ${raw.document_requests ?? "N/A"}<br>
      • Script: ${raw.script_requests ?? "N/A"}<br>
      • Stylesheet: ${raw.stylesheet_requests ?? "N/A"}<br>
      • Image: ${raw.image_requests ?? "N/A"}<br>
      • Font: ${raw.font_requests ?? "N/A"}<br>
      • XHR/Fetch: ${raw.xhr_fetch_requests ?? "N/A"}<br>
      • Other: ${raw.other_requests ?? "N/A"}<br><br>

      <strong>External Domains Contacted</strong><br>
      ${formatList(raw.external_domains || [])}<br><br>

      <strong>Download Attempt Details</strong><br>
      ${formatList(downloadList, "None")}<br><br>

      ${buildRequestList(raw.all_requests || [])}
    `;

    whyBtn.style.display = "block";
    whyBtn.textContent = "❓ Show Why";
    explanationBox.style.display = "none";
  } else {
    let riskClass = "";
    let trustIndex = result.trust_index ?? 0;
    let risk = result.risk || "Unknown";
    let triggeredRules = result.triggered_rules || [];
    let mlProb = result.ml_prob ?? 0;
    let ruleScore = result.rule_score ?? 0;

    riskClass = risk.toLowerCase();
    const trustPercent = (trustIndex * 100).toFixed(1);

    let rulesHtml = "";
    if (triggeredRules && triggeredRules.length) {
      rulesHtml = `<div class="rules"><strong>Rules triggered:</strong> ${safeText(triggeredRules.join(", "))}</div>`;
    }

    container.innerHTML = `
      <div class="risk ${riskClass}">Risk: <strong>${safeText(risk)}</strong></div>
      <div class="trust">Trust Index: ${trustPercent}%</div>
      ${rulesHtml}
      <hr>
      <div><small>ML probability: ${(mlProb * 100).toFixed(1)}%</small></div>
      <div><small>Rule score: ${(ruleScore * 100).toFixed(1)}%</small></div>
    `;

    whyBtn.style.display = "none";
    explanationBox.style.display = "none";
  }
}

// Toggle explanation box visibility
function toggleExplanation() {
  const box = document.getElementById("explanationBox");
  const btn = document.getElementById("whyBtn");

  if (box.style.display === "none" || box.style.display === "") {
    box.style.display = "block";
    btn.textContent = "❓ Hide Why";
    attachNestedRequestToggle();
  } else {
    box.style.display = "none";
    btn.textContent = "❓ Show Why";
  }
}

// Get the current tab URL
async function getCurrentTabUrl() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0]?.url;
}

// Get correct deep scan URL, even from warning page
async function getUrlForDeepScan() {
  const currentUrl = await getCurrentTabUrl();
  if (!currentUrl) return null;

  if (currentUrl.includes("/warning/warning.html")) {
    try {
      const parsed = new URL(currentUrl);
      const originalUrl = parsed.searchParams.get("url");
      return originalUrl || currentUrl;
    } catch (e) {
      return currentUrl;
    }
  }

  return currentUrl;
}

// Perform deep scan and update everything
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
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const deepResult = await response.json();

    if (deepResult.final_risk === "Phishing") {
      chrome.action.setIcon({ path: "icons/danger.png" });
    } else if (deepResult.final_risk === "Suspicious") {
      chrome.action.setIcon({ path: "icons/warning.png" });
    } else {
      chrome.action.setIcon({ path: "icons/safe.png" });
    }

    const deepScanStore = {
      url: url,
      result: deepResult,
      timestamp: Date.now()
    };
    await chrome.storage.local.set({ deepScanResult: deepScanStore });

    // keep L1+L2 metrics visible after deep scan
    await chrome.storage.local.set({
      lastResult: {
        risk: deepResult.final_risk,
        trust_index: deepResult.final_trust_index,
        ml_prob: deepResult.l1l2?.ml_prob ?? 0,
        rule_score: deepResult.l1l2?.rule_score ?? 0,
        triggered_rules: deepResult.l1l2?.triggered_rules ?? []
      }
    });

    displayResult(deepResult, true);
  } catch (error) {
    console.error("Deep scan error:", error);
    document.getElementById("result").innerHTML =
      `<p>Deep scan failed. Is the API running?<br>${safeText(error.message)}</p>`;
    document.getElementById("whyBtn").style.display = "none";
  } finally {
    loadingDiv.style.display = "none";
    btn.disabled = false;
  }
}

// On popup load, decide what to show
document.addEventListener("DOMContentLoaded", () => {
  chrome.storage.local.get(["deepScanResult", "lastResult"], async (data) => {
    const currentUrl = await getUrlForDeepScan();

    if (!currentUrl) {
      document.getElementById("result").innerHTML = "<p>Unable to get current tab URL.</p>";
      return;
    }

    const deepScanStore = data.deepScanResult;
    if (
      deepScanStore &&
      deepScanStore.url === currentUrl &&
      (Date.now() - deepScanStore.timestamp) < DEEP_SCAN_EXPIRY
    ) {
      displayResult(deepScanStore.result, true);
    } else {
      const lastResult = data.lastResult;
      if (lastResult) {
        displayResult(lastResult, false);
      } else {
        document.getElementById("result").innerHTML = "<p>No recent scan.</p>";
      }
    }
  });

  document.getElementById("deepScanBtn").addEventListener("click", runDeepScan);
  document.getElementById("whyBtn").addEventListener("click", toggleExplanation);
});