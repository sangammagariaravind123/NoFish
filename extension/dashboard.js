import {
  getCachedAuth,
  registerAuthStateListener,
  restoreSessionContext,
  signInWithEmail,
  signInWithGoogle,
  signOutUser,
  signUpWithEmail
} from "./lib/auth.js";
import { createHistoryView } from "./lib/history-view.js";
import { openExtensionPage, safeText } from "./lib/ui-utils.js";

let authFormMode = null;
let googleAuthInProgress = false;

const historyView = createHistoryView({
  limit: 10,
  showMorePath: "history.html",
  setMessage(message, isError = false) {
    const node = document.getElementById("dashboardAuthMessage");
    if (!node) return;
    node.textContent = message || "";
    node.style.color = isError ? "#b42318" : "#66788a";
  }
});

function setAuthMessage(message, isError = false) {
  const node = document.getElementById("dashboardAuthMessage");
  node.textContent = message || "";
  node.style.color = isError ? "#b42318" : "#66788a";
}

async function renderAccountSummary() {
  const auth = await getCachedAuth();
  const accountSummary = document.getElementById("accountSummary");
  const authPanel = document.getElementById("authPanel");
  const authOptions = document.getElementById("dashboardAuthOptions");

  if (auth?.email) {
    setAuthFormMode(null);
    authPanel.style.display = "none";
    accountSummary.innerHTML = `
      <div class="inline" style="justify-content:space-between; align-items:flex-start;">
        <div>
          <div class="muted">Signed in</div>
          <div style="font-weight:700; font-size:18px;">${safeText(auth.email)}</div>
          <div class="muted">${safeText(auth.provider || "email")} account</div>
        </div>
        <button id="logoutBtn" class="btn ghost">Log Out</button>
      </div>
    `;
    document.getElementById("logoutBtn").addEventListener("click", async () => {
      try {
        await signOutUser();
        await renderAccountSummary();
        await historyView.refreshHistoryView();
        setAuthMessage("Signed out.");
      } catch (error) {
        setAuthMessage(error.message || "Logout failed.", true);
      }
    });
    return;
  }

  setAuthFormMode(null);
  accountSummary.innerHTML = `
    <div class="muted">You are browsing in local-only mode. Sign in to sync history, settings, and your allow/block lists across devices.</div>
  `;
  authPanel.style.display = "block";
  authOptions.style.display = "flex";
}

function setAuthFormMode(mode) {
  authFormMode = mode;
  const form = document.getElementById("dashboardAuthForm");
  const title = document.getElementById("dashboardAuthFormTitle");
  const displayNameField = document.getElementById("dashboardDisplayNameField");
  const loginBtn = document.getElementById("dashboardLoginBtn");
  const signupBtn = document.getElementById("dashboardSignupBtn");
  const cancelBtn = document.getElementById("dashboardCancelAuthBtn");

  if (!mode) {
    form.style.display = "none";
    title.textContent = "";
    return;
  }

  form.style.display = "block";
  title.textContent = mode === "signup" ? "Create your account" : "Log in to your account";
  displayNameField.style.display = mode === "signup" ? "block" : "none";
  loginBtn.style.display = mode === "login" ? "inline-flex" : "none";
  signupBtn.style.display = mode === "signup" ? "inline-flex" : "none";
  cancelBtn.style.display = "inline-flex";
}

async function startGoogleAuth() {
  if (googleAuthInProgress) return;

  googleAuthInProgress = true;
  try {
    await signInWithGoogle();
    setAuthMessage("Continue Google sign-in in the opened tab.");
  } catch (error) {
    setAuthMessage(error.message || "Google sign-in failed.", true);
  } finally {
    googleAuthInProgress = false;
  }
}

async function handleEmailAuth(mode) {
  const email = document.getElementById("dashboardEmail").value.trim();
  const password = document.getElementById("dashboardPassword").value.trim();
  const displayName = document.getElementById("dashboardDisplayName").value.trim();

  if (!email || !password) {
    setAuthMessage("Email and password are required.", true);
    return;
  }

  try {
    if (mode === "signup") {
      await signUpWithEmail(email, password, displayName);
      setAuthMessage("Account created successfully.");
    } else {
      await signInWithEmail(email, password);
      setAuthMessage("Logged in successfully.");
    }
    setAuthFormMode(null);
    await renderAccountSummary();
    await historyView.refreshHistoryView();
  } catch (error) {
    setAuthMessage(error.message || "Authentication failed.", true);
  }
}

async function initializeDashboard() {
  document.getElementById("openSettingsBtn").addEventListener("click", () => openExtensionPage("settings.html"));
  document.getElementById("showDashboardLoginBtn").addEventListener("click", () => setAuthFormMode("login"));
  document.getElementById("showDashboardSignupBtn").addEventListener("click", () => setAuthFormMode("signup"));
  document.getElementById("dashboardCancelAuthBtn").addEventListener("click", () => setAuthFormMode(null));
  document.getElementById("dashboardLoginBtn").addEventListener("click", () => handleEmailAuth("login"));
  document.getElementById("dashboardSignupBtn").addEventListener("click", () => handleEmailAuth("signup"));
  document.getElementById("dashboardGoogleBtn").addEventListener("click", startGoogleAuth);

  registerAuthStateListener(async () => {
    await renderAccountSummary().catch((error) => {
      console.warn("Dashboard auth state render skipped:", error);
      setAuthMessage("Signed in, but some account data is still loading.", true);
    });
    await historyView.refreshHistoryView();
  });

  await renderAccountSummary();
  await restoreSessionContext().catch((error) => console.warn("Dashboard session restore skipped:", error));
  await renderAccountSummary();
  await historyView.initializeHistoryView();

  const currentUrl = new URL(window.location.href);
  if (currentUrl.searchParams.get("auth") === "google") {
    currentUrl.searchParams.delete("auth");
    window.history.replaceState({}, document.title, currentUrl.toString());
    await startGoogleAuth();
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initializeDashboard().catch((error) => {
    console.error("Dashboard init failed:", error);
    setAuthMessage(error.message || "Failed to initialize dashboard.", true);
  });
});
