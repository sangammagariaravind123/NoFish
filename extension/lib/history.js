import { MAX_LOCAL_HISTORY, RISK_ORDER, STORAGE_KEYS } from "./constants.js";
import { getValue, updateValue } from "./storage.js";
import { ensureSupabaseSession, getSupabaseClient } from "./supabase-client.js";
import { getBaseDomain, normalizeUrl } from "./url-utils.js";

function extractTriggeredRules(rawResult) {
  if (!rawResult) return [];
  if (rawResult.final_risk || rawResult.sandbox) {
    return rawResult.l1l2?.triggered_rules || [];
  }
  return rawResult.triggered_rules || [];
}

export function normalizeScanPayload(url, result, scanType = "predict", source = "navigation") {
  const isDeepScan = scanType === "deep";
  const classification = isDeepScan ? result.final_risk : result.risk;
  const trustScore = isDeepScan ? result.final_trust_index : result.trust_index;
  const l1l2 = result.l1l2 || {};
  const rawTriggeredRules = isDeepScan ? l1l2.triggered_rules || [] : result.triggered_rules || [];

  return {
    id: crypto.randomUUID(),
    url,
    domain: getBaseDomain(url),
    classification: classification || "Unknown",
    trustScore: trustScore ?? 0,
    riskScore: trustScore === null || trustScore === undefined ? null : Number(((1 - trustScore) * 100).toFixed(1)),
    mlScore: isDeepScan ? l1l2.ml_prob ?? null : result.ml_prob ?? null,
    ruleScore: isDeepScan ? l1l2.rule_score ?? null : result.rule_score ?? null,
    sandboxScore: isDeepScan ? result.sandbox?.behavioral_prob ?? null : null,
    l1l2Risk: isDeepScan ? l1l2.risk ?? null : result.risk ?? null,
    l3Risk: isDeepScan ? result.final_risk ?? null : null,
    triggeredRules: rawTriggeredRules,
    timestamp: new Date().toISOString(),
    scanType,
    source,
    rawResult: result
  };
}

async function getSessionUser() {
  const session = await ensureSupabaseSession();
  if (session?.user) {
    console.info("[PhishGuard] History module using signed-in user", session.user.email || session.user.id);
  } else {
    console.info("[PhishGuard] History module found no signed-in session.");
  }
  return session?.user ?? null;
}

async function getLocalHistory() {
  return (await getValue(STORAGE_KEYS.recentScans, [])).map(stripRawResult);
}

function mergeHistoryRecords(primaryRecords = [], fallbackRecords = []) {
  const seen = new Set();
  const merged = [];

  for (const record of [...primaryRecords, ...fallbackRecords]) {
    const key = `${record.url || ""}|${record.timestamp || ""}|${record.classification || ""}|${record.scanType || ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    merged.push(record);
  }

  return merged
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, MAX_LOCAL_HISTORY);
}

export async function persistScanRecord(payload) {
  const historyRecord = normalizeScanPayload(payload.url, payload.result, payload.scanType, payload.source);
  await persistLocalHistory(historyRecord);

  const user = await getSessionUser();
  if (user) {
    console.info("[PhishGuard] Attempting remote scan save for", user.email || user.id, payload.url);
    await persistRemoteHistory(user.id, historyRecord);
  } else {
    console.info("[PhishGuard] No signed-in session found, keeping scan in local history only.");
  }

  return historyRecord;
}

async function persistLocalHistory(record) {
  await updateValue(
    STORAGE_KEYS.recentScans,
    async (existingHistory = []) => [record, ...existingHistory].slice(0, MAX_LOCAL_HISTORY),
    []
  );

  await updateValue(
    STORAGE_KEYS.analysisLogs,
    async (existingLogs = []) => [
      { id: record.id, url: record.url, rawResult: record.rawResult, timestamp: record.timestamp },
      ...existingLogs
    ].slice(0, MAX_LOCAL_HISTORY),
    []
  );
}

async function persistRemoteHistory(userId, record) {
  const supabase = getSupabaseClient();
  const historyPayload = {
    user_id: userId,
    url: record.url,
    classification: record.classification,
    trust_score: record.trustScore,
    ml_score: record.mlScore,
    rule_score: record.ruleScore,
    sandbox_score: record.sandboxScore,
    l1l2_risk: record.l1l2Risk,
    l3_risk: record.l3Risk,
    timestamp: record.timestamp
  };

  const { error: historyError } = await supabase.from("scan_history").insert(historyPayload);
  if (historyError) {
    console.warn("[PhishGuard] Remote scan_history insert failed:", historyError.message || historyError);
    throw historyError;
  }

  if (record.rawResult) {
    const { error: logError } = await supabase.from("scan_analysis_logs").insert({
      user_id: userId,
      url: record.url,
      raw_result_json: record.rawResult,
      created_at: record.timestamp
    });

    if (logError) {
      console.warn("[PhishGuard] Remote scan_analysis_logs insert failed:", logError.message || logError);
      throw logError;
    }
  }

  console.info("[PhishGuard] Remote scan saved successfully for", record.url);
}

export async function getHistory() {
  const user = await getSessionUser();
  if (!user) {
    console.info("[PhishGuard] Dashboard history source: local only");
    return getLocalHistory();
  }

  const supabase = getSupabaseClient();
  const localHistory = await getLocalHistory();

  try {
    const [historyResult, logsResult] = await Promise.all([
      supabase
        .from("scan_history")
        .select("*")
        .eq("user_id", user.id)
        .order("timestamp", { ascending: false })
        .limit(MAX_LOCAL_HISTORY),
      supabase
        .from("scan_analysis_logs")
        .select("url, raw_result_json, created_at")
        .eq("user_id", user.id)
        .order("created_at", { ascending: false })
        .limit(MAX_LOCAL_HISTORY)
    ]);

    if (historyResult.error) throw historyResult.error;
    if (logsResult.error) throw logsResult.error;

    const logsByUrl = new Map();
    for (const log of logsResult.data || []) {
      const bucket = logsByUrl.get(log.url) || [];
      bucket.push(log);
      logsByUrl.set(log.url, bucket);
    }

    const remoteHistory = (historyResult.data || []).map((row) => {
      const candidateLogs = logsByUrl.get(row.url) || [];
      const targetTime = new Date(row.timestamp).getTime();
      const closestLog = candidateLogs.reduce((best, current) => {
        const distance = Math.abs(new Date(current.created_at).getTime() - targetTime);
        if (!best || distance < best.distance) {
          return { distance, value: current };
        }
        return best;
      }, null)?.value;

      return {
        id: row.id,
        url: row.url,
        domain: getBaseDomain(row.url),
        classification: row.classification,
        trustScore: row.trust_score,
        riskScore: row.trust_score === null || row.trust_score === undefined ? null : Number(((1 - row.trust_score) * 100).toFixed(1)),
        mlScore: row.ml_score,
        ruleScore: row.rule_score,
        sandboxScore: row.sandbox_score,
        l1l2Risk: row.l1l2_risk,
        l3Risk: row.l3_risk,
        triggeredRules: extractTriggeredRules(closestLog?.raw_result_json),
        timestamp: row.timestamp
      };
    });

    console.info("[PhishGuard] Dashboard history source: remote + local cache", {
      remote: remoteHistory.length,
      local: localHistory.length
    });
    return mergeHistoryRecords(remoteHistory, localHistory);
  } catch (error) {
    console.warn("Remote history unavailable, using local history fallback:", error.message || error);
    return localHistory;
  }
}

function stripRawResult(record) {
  const { rawResult, ...rest } = record;
  return rest;
}

export async function getAnalysisLog(record) {
  const localLogs = await getValue(STORAGE_KEYS.analysisLogs, []);
  const localMatch = localLogs.find((log) => log.id === record.id);
  if (localMatch) {
    return localMatch.rawResult;
  }

  const user = await getSessionUser();
  if (!user) return null;

  const supabase = getSupabaseClient();
  try {
    const { data, error } = await supabase
      .from("scan_analysis_logs")
      .select("raw_result_json, created_at")
      .eq("user_id", user.id)
      .eq("url", record.url)
      .order("created_at", { ascending: false })
      .limit(10);

    if (error) throw error;
    if (!data?.length) return null;

    const targetTime = new Date(record.timestamp).getTime();
    const closest = data.reduce((best, current) => {
      const currentDistance = Math.abs(new Date(current.created_at).getTime() - targetTime);
      if (!best || currentDistance < best.distance) {
        return { distance: currentDistance, value: current };
      }
      return best;
    }, null);

    return closest?.value?.raw_result_json ?? null;
  } catch (error) {
    console.warn("Remote analysis log unavailable:", error.message || error);
    return null;
  }
}

export async function recordWarningBypass(url) {
  await updateValue(
    STORAGE_KEYS.warningEvents,
    async (events = []) => [
      { id: crypto.randomUUID(), url, domain: getBaseDomain(url), timestamp: new Date().toISOString() },
      ...events
    ].slice(0, MAX_LOCAL_HISTORY),
    []
  );
}

export async function getWarningEvents() {
  return getValue(STORAGE_KEYS.warningEvents, []);
}

export function buildTrendBuckets(history) {
  const normalizedHistory = history
    .map((item) => {
      const timestamp = new Date(item.timestamp);
      const classification = normalizeClassification(item.classification || item.l3Risk || item.l1l2Risk);
      if (Number.isNaN(timestamp.getTime()) || !classification) {
        return null;
      }

      return {
        ...item,
        timestamp,
        classification
      };
    })
    .filter(Boolean);

  const anchorDate = normalizedHistory.length
    ? new Date(Math.max(...normalizedHistory.map((item) => item.timestamp.getTime())))
    : new Date();

  anchorDate.setHours(0, 0, 0, 0);

  const days = Array.from({ length: 7 }, (_, index) => {
    const date = new Date(anchorDate);
    date.setDate(anchorDate.getDate() - (6 - index));
    return {
      key: date.toISOString().slice(0, 10),
      label: date.toLocaleDateString(undefined, { weekday: "short" }),
      Safe: 0,
      Suspicious: 0,
      Phishing: 0
    };
  });

  const bucketMap = new Map(days.map((day) => [day.key, day]));

  for (const item of normalizedHistory) {
    const key = item.timestamp.toISOString().slice(0, 10);
    const bucket = bucketMap.get(key);
    if (bucket && RISK_ORDER.includes(item.classification)) {
      bucket[item.classification] += 1;
    }
  }

  return days;
}

function normalizeClassification(value) {
  const normalizedValue = String(value || "").trim().toLowerCase();
  if (!normalizedValue) return null;

  if (normalizedValue === "safe") return "Safe";
  if (normalizedValue === "suspicious") return "Suspicious";
  if (normalizedValue === "phishing") return "Phishing";
  return null;
}

export function getTopRiskyDomains(history, limit = 5) {
  const counts = new Map();

  for (const item of history) {
    if (item.classification === "Safe") continue;
    const domain = item.domain || getBaseDomain(item.url);
    counts.set(domain, (counts.get(domain) || 0) + 1);
  }

  return [...counts.entries()]
    .map(([domain, count]) => ({ domain, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

export function buildThreatTypes(history) {
  const counts = new Map();

  for (const item of history) {
    for (const rule of item.triggeredRules || []) {
      counts.set(rule, (counts.get(rule) || 0) + 1);
    }
  }

  return [...counts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);
}

export async function buildInsights(history) {
  const warningEvents = await getWarningEvents();
  const riskyHistory = history.filter((item) => item.classification !== "Safe");
  const domainCounts = new Map();
  const firstRiskyDomains = new Set();

  for (const item of riskyHistory) {
    const domain = item.domain || getBaseDomain(item.url);
    const count = domainCounts.get(domain) || 0;
    if (count === 0) {
      firstRiskyDomains.add(domain);
    }
    domainCounts.set(domain, count + 1);
  }

  const repeatedRiskyVisits = [...domainCounts.values()].filter((count) => count > 1).length;
  const frequentDomains = [...domainCounts.entries()].filter(([, count]) => count >= 3).length;

  return {
    weeklySummary: {
      safeCount: history.filter((item) => item.classification === "Safe").length,
      suspiciousCount: history.filter((item) => item.classification === "Suspicious").length,
      phishingCount: history.filter((item) => item.classification === "Phishing").length
    },
    ignoredWarnings: warningEvents.length,
    repeatedRiskyVisits,
    firstTimeRiskyVisits: firstRiskyDomains.size,
    frequentRiskyDomains: frequentDomains,
    threatTypes: buildThreatTypes(riskyHistory)
  };
}

export async function getKnownPhishingMatch(url) {
  const history = await getValue(STORAGE_KEYS.recentScans, []);
  const normalizedTargetUrl = normalizeUrl(url).toLowerCase();
  const targetDomain = getBaseDomain(url);

  const exactMatch = history.find((record) => (
    normalizeClassification(record.classification || record.l3Risk || record.l1l2Risk) === "Phishing" &&
    normalizeUrl(record.url).toLowerCase() === normalizedTargetUrl
  ));

  if (exactMatch) {
    return {
      type: "url",
      match: stripRawResult(exactMatch)
    };
  }

  const domainMatch = history.find((record) => (
    normalizeClassification(record.classification || record.l3Risk || record.l1l2Risk) === "Phishing" &&
    (record.domain || getBaseDomain(record.url)) === targetDomain
  ));

  if (domainMatch) {
    return {
      type: "domain",
      match: stripRawResult(domainMatch)
    };
  }

  return null;
}

function matchesRecord(record, targetRecord) {
  return (
    record.id === targetRecord.id ||
    (
      normalizeUrl(record.url).toLowerCase() === normalizeUrl(targetRecord.url).toLowerCase() &&
      String(record.timestamp) === String(targetRecord.timestamp) &&
      String(record.classification || "") === String(targetRecord.classification || "")
    )
  );
}

export async function deleteHistoryRecord(targetRecord) {
  await updateValue(
    STORAGE_KEYS.recentScans,
    async (records = []) => records.filter((record) => !matchesRecord(record, targetRecord)),
    []
  );

  await updateValue(
    STORAGE_KEYS.analysisLogs,
    async (logs = []) => logs.filter((log) => (
      !(normalizeUrl(log.url).toLowerCase() === normalizeUrl(targetRecord.url).toLowerCase() &&
        String(log.timestamp) === String(targetRecord.timestamp))
    )),
    []
  );

  const user = await getSessionUser();
  if (!user) return;

  const supabase = getSupabaseClient();
  console.info("[PhishGuard] Deleting history record from remote account history:", targetRecord.url);

  const { error: historyDeleteError } = await supabase
    .from("scan_history")
    .delete()
    .eq("user_id", user.id)
    .eq("url", targetRecord.url)
    .eq("timestamp", targetRecord.timestamp);

  if (historyDeleteError) {
    console.warn("[PhishGuard] Remote history delete failed:", historyDeleteError.message || historyDeleteError);
    throw historyDeleteError;
  }

  const { error: logsDeleteError } = await supabase
    .from("scan_analysis_logs")
    .delete()
    .eq("user_id", user.id)
    .eq("url", targetRecord.url)
    .eq("created_at", targetRecord.timestamp);

  if (logsDeleteError) {
    console.warn("[PhishGuard] Remote analysis log delete failed:", logsDeleteError.message || logsDeleteError);
    throw logsDeleteError;
  }
}

export async function clearHistoryRecords() {
  await updateValue(STORAGE_KEYS.recentScans, async () => [], []);
  await updateValue(STORAGE_KEYS.analysisLogs, async () => [], []);

  const user = await getSessionUser();
  if (!user) return;

  const supabase = getSupabaseClient();
  console.info("[PhishGuard] Clearing all remote scan history for", user.email || user.id);

  const { error: historyDeleteError } = await supabase
    .from("scan_history")
    .delete()
    .eq("user_id", user.id);

  if (historyDeleteError) {
    console.warn("[PhishGuard] Remote history clear failed:", historyDeleteError.message || historyDeleteError);
    throw historyDeleteError;
  }

  const { error: logsDeleteError } = await supabase
    .from("scan_analysis_logs")
    .delete()
    .eq("user_id", user.id);

  if (logsDeleteError) {
    console.warn("[PhishGuard] Remote analysis log clear failed:", logsDeleteError.message || logsDeleteError);
    throw logsDeleteError;
  }
}
