export function safeText(value) {
  if (value === null || value === undefined) return "N/A";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function formatPercent(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return "N/A";
  return `${(Number(value) * 100).toFixed(1)}%`;
}

export function formatRiskPercent(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return "N/A";
  return `${Number(value).toFixed(1)}%`;
}

export function formatDateTime(value) {
  if (!value) return "N/A";
  return new Date(value).toLocaleString();
}

export async function openExtensionPage(path) {
  await chrome.tabs.create({ url: chrome.runtime.getURL(path) });
}

export function classificationClass(value) {
  return String(value || "unknown").toLowerCase();
}
