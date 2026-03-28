// background.js

const API_URL = "http://localhost:8000/predict";

// Cache results to avoid repeated calls for same URL
let cache = new Map();

// Update toolbar icon based on risk level
function updateIcon(risk) {
  let iconPath = "";
  if (risk === "Phishing") iconPath = "icons/danger.png";
  else if (risk === "Suspicious") iconPath = "icons/warning.png";
  else iconPath = "icons/safe.png";

  chrome.action.setIcon({ path: iconPath });
}

// Check a URL by calling the API
async function checkUrl(url) {
  // Check cache first
  if (cache.has(url)) {
    return cache.get(url);
  }

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const data = await response.json();
    // Store in cache (limit cache size to prevent memory bloat)
    cache.set(url, data);
    if (cache.size > 100) {
      // remove oldest
      const oldestKey = cache.keys().next().value;
      cache.delete(oldestKey);
    }
    return data;
  } catch (error) {
    console.error("API call failed:", error);
    // On error, treat as unknown (allow navigation but show nothing)
    return { risk: "Unknown", trust_index: 0.5 };
  }
}

// Intercept navigation
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  const url = details.url;
  // Skip chrome internal pages
  if (url.startsWith("chrome://") || url.startsWith("about:")) return;

  // Show "checking" icon (optional)
  chrome.action.setIcon({ path: "icons/checking.png" });

  const result = await checkUrl(url);

  // Save result for popup
  chrome.storage.local.set({ lastResult: result });

  // Update icon
  updateIcon(result.risk);

  // If phishing, block by redirecting to warning page
  if (result.risk === "Phishing") {
    const warningUrl = chrome.runtime.getURL("warning/warning.html") +
      `?url=${encodeURIComponent(url)}&trust=${result.trust_index}&reason=${encodeURIComponent(result.triggered_rules?.join(", "))}`;
    chrome.tabs.update(details.tabId, { url: warningUrl });
  }
});