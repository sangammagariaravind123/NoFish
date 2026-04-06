import { createHistoryView } from "./lib/history-view.js";
import { openExtensionPage } from "./lib/ui-utils.js";

function setHistoryMessage(message, isError = false) {
  const node = document.getElementById("historyStatusMessage");
  if (!node) return;
  node.textContent = message || "";
  node.style.color = isError ? "#b42318" : "#66788a";
}

const historyView = createHistoryView({
  setMessage: setHistoryMessage
});

async function initializeHistoryPage() {
  document.getElementById("openDashboardBtn").addEventListener("click", () => openExtensionPage("dashboard.html"));
  document.getElementById("openSettingsBtn").addEventListener("click", () => openExtensionPage("settings.html"));
  await historyView.initializeHistoryView();
}

document.addEventListener("DOMContentLoaded", () => {
  initializeHistoryPage().catch((error) => {
    console.error("History page init failed:", error);
    setHistoryMessage(error.message || "Failed to initialize full history view.", true);
  });
});
