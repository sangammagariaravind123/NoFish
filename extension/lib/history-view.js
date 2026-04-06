import { buildExplanation, highlightSuspiciousUrl } from "./explain.js";
import {
  buildInsights,
  buildTrendBuckets,
  clearHistoryRecords,
  deleteHistoryRecord,
  getAnalysisLog,
  getHistory,
  getTopRiskyDomains
} from "./history.js";
import {
  classificationClass,
  formatDateTime,
  formatPercent,
  formatRiskPercent,
  openExtensionPage,
  safeText
} from "./ui-utils.js";

export function createHistoryView({
  limit = null,
  setMessage = () => {},
  showMorePath = null
} = {}) {
  let historyRecords = [];
  let selectedHistoryRecord = null;

  function withTimeout(promise, milliseconds, label) {
    return Promise.race([
      promise,
      new Promise((_, reject) => {
        setTimeout(() => reject(new Error(label)), milliseconds);
      })
    ]);
  }

  function setRefreshLoading(isLoading) {
    const progressNode = document.getElementById("refreshProgress");
    const refreshBtn = document.getElementById("refreshBtn");
    if (!progressNode || !refreshBtn) return;

    progressNode.classList.toggle("active", isLoading);
    refreshBtn.disabled = isLoading;
    refreshBtn.textContent = isLoading ? "Refreshing..." : "Refresh";
  }

  function getFilteredHistory() {
    const classificationFilter = document.getElementById("classificationFilter")?.value || "all";
    const recentFilter = document.getElementById("recentFilter")?.value || "all";
    const search = document.getElementById("searchInput")?.value.trim().toLowerCase() || "";

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

  function getVisibleHistory(filteredHistory) {
    return Number.isInteger(limit) ? filteredHistory.slice(0, limit) : filteredHistory;
  }

  function renderMetrics(filteredHistory) {
    const metricGrid = document.getElementById("metricGrid");
    if (!metricGrid) return;

    const safeCount = filteredHistory.filter((record) => record.classification === "Safe").length;
    const suspiciousCount = filteredHistory.filter((record) => record.classification === "Suspicious").length;
    const phishingCount = filteredHistory.filter((record) => record.classification === "Phishing").length;
    const riskyCount = filteredHistory.filter((record) => record.classification !== "Safe").length;

    metricGrid.innerHTML = [
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

  function updateHistoryFooter(filteredHistory, visibleHistory) {
    const footerNode = document.getElementById("historySummary");
    if (!footerNode) return;

    if (!filteredHistory.length) {
      footerNode.textContent = "No scan records found for the selected filters.";
      return;
    }

    if (Number.isInteger(limit) && filteredHistory.length > visibleHistory.length) {
      footerNode.textContent = `Showing the latest ${visibleHistory.length} of ${filteredHistory.length} matching scans.`;
      return;
    }

    footerNode.textContent = `Showing ${visibleHistory.length} scan record${visibleHistory.length === 1 ? "" : "s"}.`;
  }

  function updateShowMoreButton(filteredHistory) {
    const button = document.getElementById("showMoreBtn");
    if (!button) return;
    if (!showMorePath) {
      button.style.display = "none";
      return;
    }

    button.style.display = Number.isInteger(limit) && filteredHistory.length > limit ? "inline-flex" : "inline-flex";
  }

  function openDetailOverlay() {
    const overlay = document.getElementById("detailOverlay");
    if (!overlay) return;
    overlay.hidden = false;
    overlay.classList.add("active");
  }

  function closeDetailOverlay() {
    const overlay = document.getElementById("detailOverlay");
    const detailPanel = document.getElementById("detailPanel");
    selectedHistoryRecord = null;
    if (detailPanel) {
      detailPanel.textContent = "Select a scan record to inspect its analysis.";
    }
    if (!overlay) return;
    overlay.classList.remove("active");
    overlay.hidden = true;
  }

  function renderHistoryTable(filteredHistory) {
    const tableBody = document.getElementById("historyTableBody");
    if (!tableBody) return;

    const visibleHistory = getVisibleHistory(filteredHistory);
    updateHistoryFooter(filteredHistory, visibleHistory);
    updateShowMoreButton(filteredHistory);

    if (!visibleHistory.length) {
      tableBody.innerHTML = `<tr><td colspan="6" class="muted">No scan records found for the selected filters.</td></tr>`;
      return;
    }

    tableBody.innerHTML = visibleHistory.map((record, index) => `
      <tr data-index="${index}">
        <td>
          <span class="history-url-primary" title="${safeText(record.domain || record.url)}">${safeText(record.domain || record.url)}</span>
          <span class="history-url-secondary muted" title="${safeText(record.url)}">${safeText(record.url)}</span>
        </td>
        <td>${safeText(record.sourceLabel || "Local")}</td>
        <td>${formatRiskPercent(record.riskScore)}</td>
        <td><span class="pill ${classificationClass(record.classification)}">${safeText(record.classification)}</span></td>
        <td>${safeText(formatDateTime(record.timestamp))}</td>
        <td><button class="btn ghost history-action-btn" data-delete-index="${index}">Delete</button></td>
      </tr>
    `).join("");

    tableBody.querySelectorAll("tr[data-index]").forEach((row) => {
      row.addEventListener("click", async () => {
        const record = visibleHistory[Number(row.dataset.index)];
        await renderDetail(record);
      });
    });

    tableBody.querySelectorAll("button[data-delete-index]").forEach((button) => {
      button.addEventListener("click", async (event) => {
        event.stopPropagation();
        const record = visibleHistory[Number(button.dataset.deleteIndex)];
        const confirmed = window.confirm(`Delete this history entry for ${record.url}?`);
        if (!confirmed) return;

        try {
          if (selectedHistoryRecord &&
            selectedHistoryRecord.id === record.id &&
            selectedHistoryRecord.historySource === record.historySource) {
            closeDetailOverlay();
          }
          await deleteHistoryRecord(record);
          await refreshHistoryView();
        } catch (error) {
          setMessage(error.message || "Could not delete this history entry.", true);
        }
      });
    });
  }

  function renderTrendChart(filteredHistory) {
    const chartNode = document.getElementById("trendChart");
    if (!chartNode) return;

    const buckets = buildTrendBuckets(filteredHistory);
    const totalPoints = buckets.reduce((sum, bucket) => sum + bucket.Safe + bucket.Suspicious + bucket.Phishing, 0);
    if (!totalPoints) {
      chartNode.innerHTML = `<div class="muted">${filteredHistory.length ? "Scans were found, but there was not enough recent trend data to plot yet." : "No scan history yet for the selected filters."}</div>`;
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
    const topDomainsNode = document.getElementById("topDomains");
    if (!topDomainsNode) return;

    const topDomains = getTopRiskyDomains(filteredHistory);
    topDomainsNode.innerHTML = topDomains.length
      ? `<ol class="list">${topDomains.map((item) => `<li><strong>${safeText(item.domain)}</strong> <span class="muted">(${item.count} risky scans)</span></li>`).join("")}</ol>`
      : `<div class="muted">No risky domains recorded yet.</div>`;
  }

  async function renderInsights(filteredHistory) {
    const weeklySummaryNode = document.getElementById("weeklySummary");
    const securityInsightsNode = document.getElementById("securityInsights");
    if (!weeklySummaryNode || !securityInsightsNode) return;

    const insights = await buildInsights(filteredHistory);
    weeklySummaryNode.innerHTML = `
      <div class="grid grid-3">
        <div class="detail-box"><div class="muted">Safe</div><div class="metric-value">${insights.weeklySummary.safeCount}</div></div>
        <div class="detail-box"><div class="muted">Suspicious</div><div class="metric-value">${insights.weeklySummary.suspiciousCount}</div></div>
        <div class="detail-box"><div class="muted">Phishing</div><div class="metric-value">${insights.weeklySummary.phishingCount}</div></div>
      </div>
    `;

    securityInsightsNode.innerHTML = `
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
    selectedHistoryRecord = record;
    const detailPanel = document.getElementById("detailPanel");
    if (!detailPanel) return;

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
              <div class="muted">Source: ${safeText(record.sourceLabel || "Local")}</div>
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
    openDetailOverlay();
  }

  async function refreshHistoryView() {
    setRefreshLoading(true);
    try {
      historyRecords = await withTimeout(getHistory(), 6000, "History load timed out.");
      const filteredHistory = getFilteredHistory();
      const visibleHistory = getVisibleHistory(filteredHistory);
      if (selectedHistoryRecord) {
        const stillVisible = visibleHistory.some((record) => (
          record.id === selectedHistoryRecord.id &&
          record.historySource === selectedHistoryRecord.historySource
        ));
        if (!stillVisible) {
          closeDetailOverlay();
        }
      }
      renderMetrics(filteredHistory);
      renderHistoryTable(filteredHistory);
      renderTrendChart(filteredHistory);
      renderTopDomains(filteredHistory);
      await renderInsights(filteredHistory);
      setMessage("");
    } catch (error) {
      console.error("History view refresh failed:", error);
      historyRecords = [];
      renderMetrics([]);
      renderHistoryTable([]);
      renderTrendChart([]);
      renderTopDomains([]);
      await renderInsights([]);
      setMessage("History data is partially unavailable. Local features still work.", true);
    } finally {
      setRefreshLoading(false);
    }
  }

  async function initializeHistoryView() {
    document.getElementById("refreshBtn")?.addEventListener("click", refreshHistoryView);
    document.getElementById("clearHistoryBtn")?.addEventListener("click", async () => {
      const confirmed = window.confirm("Clear all scan history for the current mode?");
      if (!confirmed) return;

      try {
        await clearHistoryRecords();
        closeDetailOverlay();
        await refreshHistoryView();
      } catch (error) {
        setMessage(error.message || "Could not clear history.", true);
      }
    });
    document.getElementById("classificationFilter")?.addEventListener("change", refreshHistoryView);
    document.getElementById("recentFilter")?.addEventListener("change", refreshHistoryView);
    document.getElementById("searchInput")?.addEventListener("input", refreshHistoryView);
    document.getElementById("closeDetailBtn")?.addEventListener("click", closeDetailOverlay);
    document.getElementById("detailOverlayBackdrop")?.addEventListener("click", closeDetailOverlay);
    document.getElementById("showMoreBtn")?.addEventListener("click", async () => {
      if (showMorePath) {
        await openExtensionPage(showMorePath);
      }
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        closeDetailOverlay();
      }
    });

    await refreshHistoryView();
  }

  return {
    initializeHistoryView,
    refreshHistoryView,
    closeDetailOverlay
  };
}
