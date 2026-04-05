import { getCachedAuth, registerAuthStateListener, restoreSessionContext, signInWithEmail, signOutUser, signUpWithEmail } from "./lib/auth.js";
import { addAllowRule, addBlockRule, clearTemporaryAllows, getControlState, removeRule } from "./lib/controls.js";
import { applySecurityPreset, getSettings, saveSettings } from "./lib/settings-store.js";
import { openExtensionPage, safeText, formatDateTime } from "./lib/ui-utils.js";

function setSettingsMessage(message, isError = false) {
  const node = document.getElementById("settingsMessage");
  node.textContent = message || "";
  node.style.color = isError ? "#b42318" : "#66788a";
}

function setAuthMessage(message, isError = false) {
  const node = document.getElementById("settingsAuthMessage");
  node.textContent = message || "";
  node.style.color = isError ? "#b42318" : "#66788a";
}

async function renderAccountSummary() {
  const auth = await getCachedAuth();
  const summary = document.getElementById("settingsAccountSummary");
  const authPanel = document.getElementById("settingsAuthPanel");

  if (auth?.email) {
    authPanel.style.display = "none";
    summary.innerHTML = `
      <div class="inline" style="justify-content:space-between; align-items:flex-start;">
        <div>
          <div class="muted">Signed in</div>
          <div style="font-weight:700; font-size:18px;">${safeText(auth.email)}</div>
          <div class="muted">${safeText(auth.provider || "email")} account</div>
        </div>
        <button id="settingsLogoutBtn" class="btn ghost">Log Out</button>
      </div>
    `;
    document.getElementById("settingsLogoutBtn").addEventListener("click", async () => {
      try {
        await signOutUser();
        await renderAccountSummary();
        await refreshControlLists();
        await renderSettingsForm();
        setAuthMessage("Signed out.");
      } catch (error) {
        setAuthMessage(error.message || "Logout failed.", true);
      }
    });
    return;
  }

  summary.innerHTML = `<div class="muted">Sign in to sync settings and your allow/block lists across devices.</div>`;
  authPanel.style.display = "block";
}

async function renderSettingsForm() {
  const settings = await getSettings();
  document.getElementById("autoBlockToggle").checked = settings.autoBlockEnabled;
  document.getElementById("autoBlockPhishingToggle").checked = settings.autoBlockPhishing;
  document.getElementById("riskThreshold").value = settings.riskThreshold;
  document.getElementById("riskThresholdValue").textContent = `${settings.riskThreshold}%`;
  document.getElementById("scanMode").value = settings.scanMode;
  document.getElementById("securityMode").value = settings.securityMode;
}

function renderRuleCollection(containerId, rules, kind) {
  const container = document.getElementById(containerId);
  if (!rules.length) {
    container.innerHTML = `<div class="muted">No ${kind} rules yet.</div>`;
    return;
  }

  container.innerHTML = rules.map((rule) => `
    <div class="detail-box inline" style="justify-content:space-between;">
      <div>
        <div style="font-weight:600;">${safeText(rule.value)}</div>
        <div class="muted">${safeText(rule.type)}${rule.source === "remote" ? " • synced" : " • local only"}</div>
      </div>
      <button class="btn ghost" data-kind="${kind}" data-rule-id="${rule.id}">Remove</button>
    </div>
  `).join("");

  container.querySelectorAll("button[data-rule-id]").forEach((button) => {
    button.addEventListener("click", async () => {
      try {
        await removeRule(button.dataset.kind, button.dataset.ruleId);
        await refreshControlLists();
      } catch (error) {
        setSettingsMessage(error.message || "Could not remove the selected rule.", true);
      }
    });
  });
}

async function refreshControlLists() {
  const controls = await getControlState();
  renderRuleCollection("allowListContainer", controls.allowRules, "allow");
  renderRuleCollection("blockListContainer", controls.blockRules, "block");

  const temporaryNode = document.getElementById("temporaryAllowList");
  if (!controls.temporaryAllows.length) {
    temporaryNode.innerHTML = "No active temporary allows.";
    return;
  }

  temporaryNode.innerHTML = controls.temporaryAllows.map((entry) => `
    <div class="detail-box">
      <div style="font-weight:600;">${safeText(entry.value)}</div>
      <div class="muted">Expires ${safeText(formatDateTime(entry.expiresAt))}</div>
    </div>
  `).join("");
}

async function saveSettingsFromForm() {
  try {
    await saveSettings({
      autoBlockEnabled: document.getElementById("autoBlockToggle").checked,
      autoBlockPhishing: document.getElementById("autoBlockPhishingToggle").checked,
      riskThreshold: Number(document.getElementById("riskThreshold").value),
      scanMode: document.getElementById("scanMode").value,
      securityMode: document.getElementById("securityMode").value
    });
    setSettingsMessage("Settings saved.");
  } catch (error) {
    setSettingsMessage(error.message || "Failed to save settings.", true);
  }
}

async function applyPresetFromForm() {
  try {
    await applySecurityPreset(document.getElementById("securityMode").value);
    await renderSettingsForm();
    setSettingsMessage("Security mode preset applied.");
  } catch (error) {
    setSettingsMessage(error.message || "Could not apply security mode preset.", true);
  }
}

async function handleEmailAuth(mode) {
  const email = document.getElementById("settingsEmail").value.trim();
  const password = document.getElementById("settingsPassword").value.trim();
  const displayName = document.getElementById("settingsDisplayName").value.trim();

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
    await renderAccountSummary();
    await refreshControlLists();
    await renderSettingsForm();
  } catch (error) {
    setAuthMessage(error.message || "Authentication failed.", true);
  }
}

async function initializeSettingsPage() {
  document.getElementById("openDashboardBtn").addEventListener("click", () => openExtensionPage("dashboard.html"));
  document.getElementById("riskThreshold").addEventListener("input", (event) => {
    document.getElementById("riskThresholdValue").textContent = `${event.target.value}%`;
  });
  document.getElementById("saveSettingsBtn").addEventListener("click", saveSettingsFromForm);
  document.getElementById("applyPresetBtn").addEventListener("click", applyPresetFromForm);
  document.getElementById("addAllowBtn").addEventListener("click", async () => {
    const type = document.getElementById("allowType").value;
    const value = document.getElementById("allowValue").value.trim();
    if (!value) return;
    try {
      await addAllowRule(type, value);
      document.getElementById("allowValue").value = "";
      await refreshControlLists();
    } catch (error) {
      setSettingsMessage(error.message || "Could not save the allowlist rule.", true);
    }
  });
  document.getElementById("addBlockBtn").addEventListener("click", async () => {
    const type = document.getElementById("blockType").value;
    const value = document.getElementById("blockValue").value.trim();
    if (!value) return;
    try {
      await addBlockRule(type, value);
      document.getElementById("blockValue").value = "";
      await refreshControlLists();
    } catch (error) {
      setSettingsMessage(error.message || "Could not save the blocklist rule.", true);
    }
  });
  document.getElementById("clearTemporaryAllowsBtn").addEventListener("click", async () => {
    await clearTemporaryAllows();
    await refreshControlLists();
  });
  document.getElementById("settingsLoginBtn").addEventListener("click", () => handleEmailAuth("login"));
  document.getElementById("settingsSignupBtn").addEventListener("click", () => handleEmailAuth("signup"));
  document.getElementById("settingsGoogleBtn").addEventListener("click", async () => {
    try {
      await openExtensionPage("dashboard.html?auth=google");
      setAuthMessage("Opening Google sign-in in the dashboard tab...");
    } catch (error) {
      setAuthMessage(error.message || "Google sign-in failed.", true);
    }
  });

  registerAuthStateListener(async () => {
    await renderAccountSummary().catch((error) => {
      console.warn("Settings auth state render skipped:", error);
      setAuthMessage("Signed in, but some account controls are still loading.", true);
    });
    await refreshControlLists().catch((error) => {
      console.warn("Settings control refresh skipped:", error);
      setSettingsMessage("Local control rules are available, but sync is delayed.", true);
    });
    await renderSettingsForm().catch((error) => {
      console.warn("Settings form refresh skipped:", error);
      setSettingsMessage("Local settings are available, but sync is delayed.", true);
    });
  });

  await renderAccountSummary().catch(() => null);
  await restoreSessionContext().catch((error) => console.warn("Settings session restore skipped:", error));
  await renderAccountSummary().catch((error) => {
    console.warn("Settings account summary load skipped:", error);
    setAuthMessage("Account sync is partially unavailable right now.", true);
  });
  await renderSettingsForm().catch((error) => {
    console.warn("Settings form load skipped:", error);
    setSettingsMessage("Could not load some settings. Local defaults are still available.", true);
  });
  await refreshControlLists().catch((error) => {
    console.warn("Control list load skipped:", error);
    setSettingsMessage("Could not load some control rules. Local rules are still available.", true);
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initializeSettingsPage().catch((error) => {
    console.error("Settings init failed:", error);
    setSettingsMessage(error.message || "Failed to initialize settings.", true);
  });
});
