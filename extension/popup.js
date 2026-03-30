// popup.js

let currentUrl = null;

// Helper to display L1+L2 result (or deep scan result)
function displayResult(result, isDeepScan = false) {
  const container = document.getElementById("result");
  if (!result) {
    container.innerHTML = "<p>No recent scan.</p>";
    return;
  }

  let riskClass = "";
  let trustIndex = result.trust_index;
  let risk = result.risk;
  let triggeredRules = result.triggered_rules || [];
  let mlProb = result.ml_prob;
  let ruleScore = result.rule_score;

  // For deep scan result, the structure is different: contains final_risk, final_trust_index, l1l2, sandbox
  if (isDeepScan) {
    risk = result.final_risk;
    trustIndex = result.final_trust_index;
    riskClass = risk.toLowerCase();
    triggeredRules = result.l1l2?.triggered_rules || [];
    mlProb = result.l1l2?.ml_prob;
    ruleScore = result.l1l2?.rule_score;

    // Show sandbox details
    const sandboxProb = result.sandbox?.behavioral_prob;
    const explanation = result.explanation;

    container.innerHTML = `
      <div class="risk ${riskClass}">Risk: <strong>${risk}</strong></div>
      <div class="trust">Trust Index: ${(trustIndex * 100).toFixed(1)}%</div>
      <div class="rules"><strong>Deep Scan:</strong> ${explanation}</div>
      <div><small>Sandbox behavioral probability: ${sandboxProb ? (sandboxProb * 100).toFixed(1) : 'N/A'}%</small></div>
      <hr>
      <div><small>L1+L2: ${risk} (Trust: ${(trustIndex * 100).toFixed(1)}%)</small></div>
      <div><small>ML probability: ${mlProb ? (mlProb * 100).toFixed(1) : 'N/A'}%</small></div>
      <div><small>Rule score: ${ruleScore ? (ruleScore * 100).toFixed(1) : 'N/A'}%</small></div>
      <div class="rules"><strong>Rules triggered:</strong> ${triggeredRules.join(", ") || "None"}</div>
    `;
  } else {
    riskClass = risk.toLowerCase();
    const trustPercent = (trustIndex * 100).toFixed(1);
    let rulesHtml = "";
    if (triggeredRules && triggeredRules.length) {
      rulesHtml = `<div class="rules"><strong>Rules triggered:</strong> ${triggeredRules.join(", ")}</div>`;
    }
    container.innerHTML = `
      <div class="risk ${riskClass}">Risk: <strong>${risk}</strong></div>
      <div class="trust">Trust Index: ${trustPercent}%</div>
      ${rulesHtml}
      <hr>
      <div><small>ML probability: ${(mlProb * 100).toFixed(1)}%</small></div>
      <div><small>Rule score: ${(ruleScore * 100).toFixed(1)}%</small></div>
    `;
  }
}

// Fetch the current tab's URL and then call deep scan
async function runDeepScan() {
  const loadingDiv = document.getElementById("loading");
  loadingDiv.style.display = "block";

  // Get current tab URL
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tabs[0].url;
  if (!url) {
    loadingDiv.style.display = "none";
    displayResult(null);
    return;
  }

  try {
    const response = await fetch("http://localhost:8000/deep_scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    });
    if (!response.ok) throw new Error("Deep scan failed");
    const result = await response.json();
    // Store the result for future popups? Not necessary, but we can store in storage for later.
    chrome.storage.local.set({ deepScanResult: result });
    displayResult(result, true);
  } catch (error) {
    console.error(error);
    document.getElementById("result").innerHTML = "<p>Deep scan failed. Is the API running?</p>";
  } finally {
    loadingDiv.style.display = "none";
  }
}

// On popup load, get the last result from storage (the one set by background script on navigation)
chrome.storage.local.get("lastResult", (data) => {
  const result = data.lastResult;
  if (result) {
    displayResult(result);
  } else {
    document.getElementById("result").innerHTML = "<p>No recent scan.</p>";
  }
});

// Attach deep scan button listener
document.getElementById("deepScanBtn").addEventListener("click", runDeepScan);