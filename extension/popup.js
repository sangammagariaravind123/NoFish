// popup.js

chrome.storage.local.get("lastResult", (data) => {
  const result = data.lastResult;
  const container = document.getElementById("result");
  if (!result) {
    container.innerHTML = "<p>No recent scan.</p>";
    return;
  }

  const riskClass = result.risk.toLowerCase();
  const trustPercent = (result.trust_index * 100).toFixed(1);

  let rulesHtml = "";
  if (result.triggered_rules && result.triggered_rules.length) {
    rulesHtml = `<div class="rules"><strong>Rules triggered:</strong> ${result.triggered_rules.join(", ")}</div>`;
  }

  container.innerHTML = `
    <div class="risk ${riskClass}">Risk: <strong>${result.risk}</strong></div>
    <div class="trust">Trust Index: ${trustPercent}%</div>
    ${rulesHtml}
    <hr>
    <div><small>ML probability: ${(result.ml_prob*100).toFixed(1)}%</small></div>
    <div><small>Rule score: ${(result.rule_score*100).toFixed(1)}%</small></div>
  `;
});