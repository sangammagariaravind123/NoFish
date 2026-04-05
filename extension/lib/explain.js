const URL_KEYWORDS = ["login", "verify", "update", "secure", "account", "bank", "payment", "signin", "confirm"];
const SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq"];

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function highlightSuspiciousUrl(url) {
  let highlighted = escapeHtml(url);

  for (const keyword of URL_KEYWORDS) {
    const regex = new RegExp(keyword, "gi");
    highlighted = highlighted.replace(regex, (match) => `<mark>${match}</mark>`);
  }

  for (const tld of SUSPICIOUS_TLDS) {
    const regex = new RegExp(tld.replace(".", "\\."), "gi");
    highlighted = highlighted.replace(regex, (match) => `<mark>${match}</mark>`);
  }

  highlighted = highlighted.replace(/@/g, "<mark>@</mark>");
  return highlighted;
}

export function buildExplanation(result, isDeepScan = false) {
  const risk = isDeepScan ? result.final_risk : result.risk;
  const l1l2 = result.l1l2 || {};
  const triggeredRules = isDeepScan ? l1l2.triggered_rules || [] : result.triggered_rules || [];
  const sandboxProb = result.sandbox?.behavioral_prob ?? null;

  const why = [];
  const impact = [];

  if (triggeredRules.length) {
    why.push(`Triggered rule signals: ${triggeredRules.join(", ")}.`);
  }

  if (sandboxProb !== null && sandboxProb >= 0.4) {
    why.push(`The sandbox saw suspicious runtime behavior with a score of ${(sandboxProb * 100).toFixed(1)}%.`);
  }

  if (!why.length) {
    why.push("The detector saw enough low-confidence or mixed signals to avoid calling the page fully safe.");
  }

  if (risk === "Phishing") {
    impact.push("This page could try to capture passwords, payment details, or account recovery data.");
    impact.push("Proceeding may expose you to credential theft or malicious redirects.");
  } else if (risk === "Suspicious") {
    impact.push("This page shows warning signs and should be treated carefully before entering sensitive information.");
    impact.push("A deep scan or manual verification is recommended.");
  } else {
    impact.push("No strong phishing indicators were found in the current scan.");
    impact.push("You should still verify unusual login or payment requests before proceeding.");
  }

  return {
    why,
    impact,
    breakdown: [
      {
        label: "ML score",
        value: isDeepScan ? l1l2.ml_prob ?? null : result.ml_prob ?? null
      },
      {
        label: "Rule score",
        value: isDeepScan ? l1l2.rule_score ?? null : result.rule_score ?? null
      },
      {
        label: "Sandbox score",
        value: sandboxProb
      }
    ]
  };
}
