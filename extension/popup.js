const DEEP_SCAN_EXPIRY = 5 * 60 * 1000; // 5 minutes

function formatList(items, emptyText = "None") {
  if (!items || !items.length) return emptyText;
  return items.map(item => `• ${item}`).join("<br>");
}

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
    const riskClass = risk.toLowerCase();
    const trustIndex = result.final_trust_index ?? 0;
    const sandboxProb = result.sandbox?.behavioral_prob;
    const raw = result.sandbox?.raw_output || {};

    container.innerHTML = `
      <div class="risk ${riskClass}">Risk: <strong>${risk}</strong></div>
      <div class="trust">Trust Index: ${(trustIndex * 100).toFixed(1)}%</div>
      <div><small>Sandbox behavioral probability: ${
        sandboxProb !== undefined ? (sandboxProb * 100).toFixed(1) : "N/A"
      }%</small></div>
      <hr>
      <div class="rules"><strong>Scanned URL:</strong> ${result.scanned_url || "N/A"}</div>
      <div class="rules"><strong>Final URL:</strong> ${raw.final_url || "N/A"}</div>
    `;

    const downloadList = (raw.download_attempts || []).map(
      d => `${d.suggested_filename || "unknown"} (${d.url || "no url"})`
    );

    const explanationHtml = `
      <strong>🔬 Sandbox Output</strong><br><br>

      <strong>Original URL:</strong><br>${raw.url || "N/A"}<br><br>
      <strong>Final URL:</strong><br>${raw.final_url || "N/A"}<br><br>

      <strong>Behavior Summary</strong><br>
      • Total requests: ${raw.total_requests ?? "N/A"}<br>
      • External domain count: ${raw.external_domain_count ?? "N/A"}<br>
      • Redirect count: ${raw.redirect_count ?? "N/A"}<br>
      • JavaScript requests: ${raw.js_requests ?? "N/A"}<br>
      • IP-based requests: ${raw.ip_based_requests ?? "N/A"}<br>
      • Suspicious TLD count: ${raw.suspicious_tld_count ?? "N/A"}<br>
      • Download attempts: ${(raw.download_attempts || []).length}<br><br>

      <strong>External Domains Contacted</strong><br>
      ${formatList(raw.external_domains || [])}<br><br>

      <strong>Download Attempt Details</strong><br>
      ${formatList(downloadList, "None")}<br><br>

      <strong>All Requests (first 15)</strong><br>
      ${formatList((raw.all_requests || []).slice(0, 15), "None")}
      ${(raw.all_requests || []).length > 15 ? "<br>• ...truncated..." : ""}
    `;

    explanationBox.innerHTML = explanationHtml;
    whyBtn.style.display = "block";
    whyBtn.textContent = "❓ Show Why";
    explanationBox.style.display = "none";
  } else {
    const risk = result.risk || "Unknown";
    const riskClass = risk.toLowerCase();
    const trustIndex = result.trust_index ?? 0;
    const mlProb = result.ml_prob ?? 0;
    const ruleScore = result.rule_score ?? 0;
    const triggeredRules = result.triggered_rules || [];

    let rulesHtml = "";
    if (triggeredRules.length) {
      rulesHtml = `<div class="rules"><strong>Rules triggered:</strong> ${triggeredRules.join(", ")}</div>`;
    }

    container.innerHTML = `
      <div class="risk ${riskClass}">Risk: <strong>${risk}</strong></div>
      <div class="trust">Trust Index: ${(trustIndex * 100).toFixed(1)}%</div>
      ${rulesHtml}
      <hr>
      <div><small>ML probability: ${(mlProb * 100).toFixed(1)}%</small></div>
      <div><small>Rule score: ${(ruleScore * 100).toFixed(1)}%</small></div>
    `;

    whyBtn.style.display = "none";
    explanationBox.style.display = "none";
  }
}

function toggleExplanation() {
  const box = document.getElementById("explanationBox");
  const btn = document.getElementById("whyBtn");

  if (box.style.display === "none") {
    box.style.display = "block";
    btn.textContent = "❓ Hide Why";
  } else {
    box.style.display = "none";
    btn.textContent = "❓ Show Why";
  }
}

async function getCurrentTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0];
}

async function getUrlForDeepScan() {
  const tab = await getCurrentTab();
  const currentUrl = tab?.url;

  if (!currentUrl) return null;

  // If user is on extension warning page, extract original blocked URL
  if (currentUrl.includes("/warning/warning.html")) {
    try {
      const parsed = new URL(currentUrl);
      const originalUrl = parsed.searchParams.get("url");
      return originalUrl || currentUrl;
    } catch {
      return currentUrl;
    }
  }

  return currentUrl;
}

async function runDeepScan() {
  const loadingDiv = document.getElementById("loading");
  const btn = document.getElementById("deepScanBtn");
  const whyBtn = document.getElementById("whyBtn");
  const explanationBox = document.getElementById("explanationBox");

  loadingDiv.style.display = "block";
  btn.disabled = true;
  whyBtn.style.display = "none";
  explanationBox.style.display = "none";

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

    if (deepResult.final_risk === "Phishing") {
      chrome.action.setIcon({ path: "icons/danger.png" });
    } else if (deepResult.final_risk === "Suspicious") {
      chrome.action.setIcon({ path: "icons/warning.png" });
    } else {
      chrome.action.setIcon({ path: "icons/safe.png" });
    }

    const deepScanStore = {
      url,
      result: deepResult,
      timestamp: Date.now()
    };

    await chrome.storage.local.set({ deepScanResult: deepScanStore });

    await chrome.storage.local.set({
      lastResult: {
        risk: deepResult.final_risk,
        trust_index: deepResult.final_trust_index
      }
    });

    displayResult(deepResult, true);
  } catch (error) {
    console.error("Deep scan error:", error);
    document.getElementById("result").innerHTML =
      `<p>Deep scan failed. Is the API running?<br>${error.message}</p>`;
    whyBtn.style.display = "none";
    explanationBox.style.display = "none";
  } finally {
    loadingDiv.style.display = "none";
    btn.disabled = false;
  }
}

chrome.storage.local.get(["deepScanResult", "lastResult"], async (data) => {
  const url = await getUrlForDeepScan();

  if (!url) {
    document.getElementById("result").innerHTML = "<p>Unable to get current tab URL.</p>";
    return;
  }

  const deepScanStore = data.deepScanResult;

  if (
    deepScanStore &&
    deepScanStore.url === url &&
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