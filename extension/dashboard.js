import { getCachedAuth, registerAuthStateListener, restoreSessionContext, signInWithEmail, signInWithGoogle, signOutUser, signUpWithEmail } from "./lib/auth.js";
import { buildExplanation, highlightSuspiciousUrl } from "./lib/explain.js";
import { buildInsights, buildTrendBuckets, getAnalysisLog, getHistory, getTopRiskyDomains } from "./lib/history.js";
import { openExtensionPage, safeText, formatDateTime, formatPercent, formatRiskPercent, classificationClass } from "./lib/ui-utils.js";

let historyRecords = [];
let authFormMode = null;

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
  const authForm = document.getElementById("dashboardAuthForm");

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
      await signOutUser();
      await renderAccountSummary();
      await refreshDashboard();
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

function getFilteredHistory() {
  const classificationFilter = document.getElementById("classificationFilter").value;
  const recentFilter = document.getElementById("recentFilter").value;
  const search = document.getElementById("searchInput").value.trim().toLowerCase();

  return historyRecords.filter((record) => {
    if (classificationFilter !== "all" && record.classification !== classificationFilter) {
      return false;
    }

    if (recentFilter !== "all") {
      const cutoff = Date.now() - Number(recentFilter) * 24 * 60 * 60 * 1000;
      if (new Date(record.timestamp).getTime() < cutoff) {
        return false;
      }
    }

    if (search) {
      const target = `${record.url} ${record.domain}`.toLowerCase();
      if (!target.includes(search)) {
        return false;
      }
    }

    return true;
  });
}

function renderMetrics(filteredHistory) {
  const safeCount = filteredHistory.filter((record) => record.classification === "Safe").length;
  const suspiciousCount = filteredHistory.filter((record) => record.classification === "Suspicious").length;
  const phishingCount = filteredHistory.filter((record) => record.classification === "Phishing").length;
  const riskyCount = filteredHistory.filter((record) => record.classification !== "Safe").length;

  document.getElementById("metricGrid").innerHTML = [
    { label: "Total scans", value: filteredHistory.length },
    { label: "Safe", value: safeCount },
    { label: "Suspicious", value: suspiciousCount },
    { label: "Phishing", value: phishingCount },
    { label: "Risky visits", value: riskyCount }
  ].map((metric) => `
    <div class="card">
      <div class="muted">${metric.label}</div>
      <div class="metric-value">${metric.value}</div>
    </div>
  `).join("");
}

function renderHistoryTable(filteredHistory) {
  const tableBody = document.getElementById("historyTableBody");
  if (!filteredHistory.length) {
    tableBody.innerHTML = `<tr><td colspan="4" class="muted">No scan records found for the selected filters.</td></tr>`;
    return;
  }

  tableBody.innerHTML = filteredHistory.map((record, index) => `
    <tr data-index="${index}">
      <td>
        <div style="font-weight:600;">${safeText(record.domain || record.url)}</div>
        <div class="muted">${safeText(record.url)}</div>
      </td>
      <td>${formatRiskPercent(record.riskScore)}</td>
      <td><span class="pill ${classificationClass(record.classification)}">${safeText(record.classification)}</span></td>
      <td>${safeText(formatDateTime(record.timestamp))}</td>
    </tr>
  `).join("");

  tableBody.querySelectorAll("tr[data-index]").forEach((row) => {
    row.addEventListener("click", async () => {
      const record = filteredHistory[Number(row.dataset.index)];
      await renderDetail(record);
    });
  });
}

function renderTrendChart(filteredHistory) {
  const chartNode = document.getElementById("trendChart");
  const buckets = buildTrendBuckets(filteredHistory);
  const totalPoints = buckets.reduce((sum, bucket) => sum + bucket.Safe + bucket.Suspicious + bucket.Phishing, 0);
  if (!totalPoints) {
    chartNode.innerHTML = `<div class="muted">No scan history yet for the selected filters.</div>`;
    return;
  }
  const maxValue = Math.max(1, ...buckets.map((bucket) => bucket.Safe + bucket.Suspicious + bucket.Phishing));

  chartNode.innerHTML = buckets.map((bucket) => {
    const safeHeight = bucket.Safe ? Math.max(8, (bucket.Safe / maxValue) * 140) : 0;
    const suspiciousHeight = bucket.Suspicious ? Math.max(8, (bucket.Suspicious / maxValue) * 140) : 0;
    const phishingHeight = bucket.Phishing ? Math.max(8, (bucket.Phishing / maxValue) * 140) : 0;
    return `
      <div class="chart-day">
        <div class="chart-stack">
          <div class="chart-segment phishing" style="height:${phishingHeight}px;"></div>
          <div class="chart-segment suspicious" style="height:${suspiciousHeight}px;"></div>
          <div class="chart-segment safe" style="height:${safeHeight}px;"></div>
        </div>
        <div class="muted">${bucket.label}</div>
      </div>
    `;
  }).join("");
}

function renderTopDomains(filteredHistory) {
  const topDomains = getTopRiskyDomains(filteredHistory);
  document.getElementById("topDomains").innerHTML = topDomains.length
    ? `<ol class="list">${topDomains.map((item) => `<li><strong>${safeText(item.domain)}</strong> <span class="muted">(${item.count} risky scans)</span></li>`).join("")}</ol>`
    : `<div class="muted">No risky domains recorded yet.</div>`;
}

async function renderInsights(filteredHistory) {
  const insights = await buildInsights(filteredHistory);
  document.getElementById("weeklySummary").innerHTML = `
    <div class="grid grid-3">
      <div class="detail-box"><div class="muted">Safe</div><div class="metric-value">${insights.weeklySummary.safeCount}</div></div>
      <div class="detail-box"><div class="muted">Suspicious</div><div class="metric-value">${insights.weeklySummary.suspiciousCount}</div></div>
      <div class="detail-box"><div class="muted">Phishing</div><div class="metric-value">${insights.weeklySummary.phishingCount}</div></div>
    </div>
  `;

  document.getElementById("securityInsights").innerHTML = `
    <div class="stack">
      <div class="detail-box"><strong>Ignored warnings:</strong> ${insights.ignoredWarnings}</div>
      <div class="detail-box"><strong>Repeated risky visits:</strong> ${insights.repeatedRiskyVisits}</div>
      <div class="detail-box"><strong>First-time risky domains:</strong> ${insights.firstTimeRiskyVisits}</div>
      <div class="detail-box"><strong>Frequent risky domains:</strong> ${insights.frequentRiskyDomains}</div>
      <div class="detail-box">
        <strong>Common threat types</strong>
        ${insights.threatTypes.length ? `<div class="tag-row">${insights.threatTypes.slice(0, 8).map((item) => `<span class="tag">${safeText(item.name)} (${item.count})</span>`).join("")}</div>` : `<div class="muted">Not enough triggered-rule data yet.</div>`}
      </div>
    </div>
  `;
}

async function renderDetail(record) {
  const detailPanel = document.getElementById("detailPanel");
  const rawResult = await getAnalysisLog(record);
  const isDeep = Boolean(rawResult?.final_risk || rawResult?.sandbox);
  const explanation = rawResult ? buildExplanation(rawResult, isDeep) : null;
  const triggeredRules = isDeep ? rawResult?.l1l2?.triggered_rules || [] : rawResult?.triggered_rules || [];

  detailPanel.innerHTML = `
    <div class="stack">
      <div class="detail-box">
        <div class="inline" style="justify-content:space-between;">
          <div>
            <div class="muted">URL</div>
            <div style="font-weight:700;">${safeText(record.url)}</div>
          </div>
          <span class="pill ${classificationClass(record.classification)}">${safeText(record.classification)}</span>
        </div>
      </div>
      <div class="detail-box">
        <strong>Decision breakdown</strong><br>
        • Trust score: ${formatPercent(record.trustScore)}<br>
        • ML score: ${formatPercent(record.mlScore)}<br>
        • Rule score: ${formatPercent(record.ruleScore)}<br>
        • Sandbox score: ${formatPercent(record.sandboxScore)}
      </div>
      <div class="detail-box">
        <strong>Triggered rules</strong><br>
        ${triggeredRules.length ? triggeredRules.map((item) => `• ${safeText(item)}`).join("<br>") : "No rule triggers stored for this record."}
      </div>
      <div class="detail-box">
        <strong>Suspicious URL parts</strong><br>
        <div>${highlightSuspiciousUrl(record.url)}</div>
      </div>
      ${explanation ? `
        <div class="detail-box">
          <strong>Why this may be phishing</strong><br>
          ${explanation.why.map((item) => `• ${safeText(item)}`).join("<br>")}
        </div>
        <div class="detail-box">
          <strong>What might happen if you proceed</strong><br>
          ${explanation.impact.map((item) => `• ${safeText(item)}`).join("<br>")}
        </div>
      ` : ""}
      <div class="detail-box">
        <strong>Raw analysis log</strong>
        <pre class="code-block">${safeText(JSON.stringify(rawResult || record, null, 2))}</pre>
      </div>
    </div>
  `;
}

async function refreshDashboard() {
  try {
    historyRecords = await getHistory();
    const filteredHistory = getFilteredHistory();
    renderMetrics(filteredHistory);
    renderHistoryTable(filteredHistory);
    renderTrendChart(filteredHistory);
    renderTopDomains(filteredHistory);
    await renderInsights(filteredHistory);
  } catch (error) {
    console.error("Dashboard refresh failed:", error);
    historyRecords = [];
    renderMetrics([]);
    renderHistoryTable([]);
    renderTrendChart([]);
    renderTopDomains([]);
    await renderInsights([]);
    setAuthMessage("Dashboard data is partially unavailable. Local features still work.", true);
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
    await refreshDashboard();
  } catch (error) {
    setAuthMessage(error.message || "Authentication failed.", true);
  }
}

async function initializeDashboard() {
  document.getElementById("openSettingsBtn").addEventListener("click", () => openExtensionPage("settings.html"));
  document.getElementById("refreshBtn").addEventListener("click", refreshDashboard);
  document.getElementById("classificationFilter").addEventListener("change", refreshDashboard);
  document.getElementById("recentFilter").addEventListener("change", refreshDashboard);
  document.getElementById("searchInput").addEventListener("input", refreshDashboard);
  document.getElementById("showDashboardLoginBtn").addEventListener("click", () => setAuthFormMode("login"));
  document.getElementById("showDashboardSignupBtn").addEventListener("click", () => setAuthFormMode("signup"));
  document.getElementById("dashboardCancelAuthBtn").addEventListener("click", () => setAuthFormMode(null));
  document.getElementById("dashboardLoginBtn").addEventListener("click", () => handleEmailAuth("login"));
  document.getElementById("dashboardSignupBtn").addEventListener("click", () => handleEmailAuth("signup"));
  document.getElementById("dashboardGoogleBtn").addEventListener("click", async () => {
    try {
      await signInWithGoogle();
      setAuthMessage("Google sign-in opened in a new tab.");
    } catch (error) {
      setAuthMessage(error.message || "Google sign-in failed.", true);
    }
  });

  registerAuthStateListener(async () => {
    await renderAccountSummary().catch((error) => {
      console.warn("Dashboard auth state render skipped:", error);
      setAuthMessage("Signed in, but some account data is still loading.", true);
    });
    await refreshDashboard();
  });

  await restoreSessionContext().catch((error) => console.warn("Dashboard session restore skipped:", error));
  await renderAccountSummary();
  await refreshDashboard();
}

document.addEventListener("DOMContentLoaded", () => {
  initializeDashboard().catch((error) => {
    console.error("Dashboard init failed:", error);
    setAuthMessage(error.message || "Failed to initialize dashboard.", true);
  });
});
