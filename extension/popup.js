// popup.js

const DEEP_SCAN_EXPIRY = 5 * 60 * 1000; // 5 minutes

// Display either normal L1+L2 result or deep scan result
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

  if (isDeepScan) {
    risk = result.final_risk;
    trustIndex = result.final_trust_index;
    riskClass = risk.toLowerCase();
    triggeredRules = result.l1l2?.triggered_rules || [];
    mlProb = result.l1l2?.ml_prob;
    ruleScore = result.l1l2?.rule_score;

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

// Get the current tab URL
async function getCurrentTabUrl() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0]?.url;
}

// Perform deep scan and update everything
async function runDeepScan() {
  const loadingDiv = document.getElementById("loading");
  loadingDiv.style.display = "block";
  const btn = document.getElementById("deepScanBtn");
  btn.disabled = true;

  const url = await getCurrentTabUrl();
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

    // 1. Update toolbar icon based on final risk
    if (deepResult.final_risk === "Phishing") {
      chrome.action.setIcon({ path: "icons/danger.png" });
    } else if (deepResult.final_risk === "Suspicious") {
      chrome.action.setIcon({ path: "icons/warning.png" });
    } else {
      chrome.action.setIcon({ path: "icons/safe.png" });
    }

    // 2. Store deep scan result with URL and timestamp
    const deepScanStore = {
      url: url,
      result: deepResult,
      timestamp: Date.now()
    };
    await chrome.storage.local.set({ deepScanResult: deepScanStore });

    // 3. Overwrite lastResult so the popup immediately shows deep scan result
    //    This is used when the popup is already open (we'll also display it directly)
    await chrome.storage.local.set({
      lastResult: {
        risk: deepResult.final_risk,
        trust_index: deepResult.final_trust_index,
        ml_prob: deepResult.l1l2.ml_prob,
        rule_score: deepResult.l1l2.rule_score,
        triggered_rules: deepResult.l1l2.triggered_rules
      }
    });

    // 4. Display the deep result right now in the popup
    displayResult(deepResult, true);
  } catch (error) {
    console.error("Deep scan error:", error);
    document.getElementById("result").innerHTML = `<p>Deep scan failed. Is the API running?<br>${error.message}</p>`;
  } finally {
    loadingDiv.style.display = "none";
    btn.disabled = false;
  }
}

// On popup load, decide what to show
chrome.storage.local.get(["deepScanResult", "lastResult"], async (data) => {
  const currentUrl = await getCurrentTabUrl();
  if (!currentUrl) {
    document.getElementById("result").innerHTML = "<p>Unable to get current tab URL.</p>";
    return;
  }

  const deepScanStore = data.deepScanResult;
  if (deepScanStore && deepScanStore.url === currentUrl && (Date.now() - deepScanStore.timestamp) < DEEP_SCAN_EXPIRY) {
    // Show deep scan result if it's for the current URL and not too old
    displayResult(deepScanStore.result, true);
  } else {
    // Otherwise show the normal lastResult from background (L1+L2)
    const lastResult = data.lastResult;
    if (lastResult) {
      displayResult(lastResult);
    } else {
      document.getElementById("result").innerHTML = "<p>No recent scan.</p>";
    }
  }
});

// Attach deep scan button listener
document.getElementById("deepScanBtn").addEventListener("click", runDeepScan);