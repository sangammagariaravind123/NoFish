import { exchangeCodeForSession } from "./lib/auth.js";

const messageNode = document.getElementById("callbackMessage");
const dashboardBtn = document.getElementById("openDashboardBtn");

function openDashboard() {
  window.location.href = chrome.runtime.getURL("dashboard.html?auth=success");
}

dashboardBtn.addEventListener("click", openDashboard);

async function init() {
  try {
    const session = await exchangeCodeForSession(window.location.href);
    if (!session) {
      throw new Error("No auth session information was found in the callback URL.");
    }
    messageNode.textContent = "Sign-in complete. Redirecting to your dashboard...";
    dashboardBtn.style.display = "inline-flex";
    setTimeout(openDashboard, 1500);
  } catch (error) {
    messageNode.textContent = error.message || "We could not finish sign-in. You can retry from the extension popup.";
    dashboardBtn.textContent = "Open Dashboard";
    dashboardBtn.style.display = "inline-flex";
  }
}

init();
