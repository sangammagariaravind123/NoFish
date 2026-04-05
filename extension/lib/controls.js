import { DEFAULT_CONTROL_RULES, STORAGE_KEYS, TEMP_ALLOW_MINUTES } from "./constants.js";
import { getValue, setValue } from "./storage.js";
import { ensureSupabaseSession, getSupabaseClient } from "./supabase-client.js";
import { getBaseDomain, makeDomainRule, matchesRule, normalizeUrl } from "./url-utils.js";

function normalizeRules(state = {}) {
  return {
    allowRules: Array.isArray(state.allowRules) ? state.allowRules : [],
    blockRules: Array.isArray(state.blockRules) ? state.blockRules : [],
    temporaryAllows: Array.isArray(state.temporaryAllows) ? state.temporaryAllows : []
  };
}

async function getSessionUser() {
  const session = await ensureSupabaseSession();
  if (session?.user) {
    console.info("[PhishGuard] Controls module using signed-in user", session.user.email || session.user.id);
  } else {
    console.info("[PhishGuard] Controls module found no signed-in session.");
  }
  return session?.user ?? null;
}

export async function getControlState() {
  const state = normalizeRules(await getValue(STORAGE_KEYS.controls, DEFAULT_CONTROL_RULES));
  const activeTemporaryAllows = state.temporaryAllows.filter((entry) => new Date(entry.expiresAt).getTime() > Date.now());
  if (activeTemporaryAllows.length !== state.temporaryAllows.length) {
    const nextState = { ...state, temporaryAllows: activeTemporaryAllows };
    await setValue(STORAGE_KEYS.controls, nextState);
    return nextState;
  }
  return state;
}

async function saveControlState(nextState) {
  const normalized = normalizeRules(nextState);
  await setValue(STORAGE_KEYS.controls, normalized);
  return normalized;
}

function buildRule(type, value, source = "local", remoteId = null) {
  return {
    id: crypto.randomUUID(),
    type,
    value: String(value || "").trim().toLowerCase(),
    source,
    remoteId,
    createdAt: new Date().toISOString()
  };
}

async function syncRuleRemote(table, rule) {
  const user = await getSessionUser();
  if (!user) return null;

  const supabase = getSupabaseClient();
  const payload = table === "blocklist"
    ? {
      user_id: user.id,
      domain: rule.type === "domain" ? rule.value : "",
      rule_type: rule.type,
      rule_value: rule.value,
      created_at: new Date().toISOString()
    }
    : {
      user_id: user.id,
      domain: rule.value,
      created_at: new Date().toISOString()
    };

  const onConflict = table === "blocklist" ? "user_id,rule_type,rule_value" : "user_id,domain";
  console.info("[PhishGuard] Saving remote control rule:", table, payload);
  const { error } = await supabase.from(table).upsert(payload, { onConflict });
  if (error) throw error;
  return payload;
}

async function removeRuleRemote(table, rule) {
  const user = await getSessionUser();
  if (!user) return;

  const supabase = getSupabaseClient();
  let query = supabase
    .from(table)
    .delete()
    .eq("user_id", user.id);

  if (table === "blocklist") {
    query = query
      .eq("rule_type", rule.type)
      .eq("rule_value", rule.value);
  } else {
    query = query.eq("domain", rule.value);
  }

  console.info("[PhishGuard] Removing remote control rule:", table, rule);
  const { error } = await query;

  if (error) throw error;
}

export async function addAllowRule(type, value) {
  const controlState = await getControlState();
  const nextRule = type === "domain" ? makeDomainRule(value, null, "local") : buildRule(type, value);
  const nextState = {
    ...controlState,
    allowRules: [nextRule, ...controlState.allowRules.filter((rule) => !(rule.type === nextRule.type && rule.value === nextRule.value))]
  };

  const savedState = await saveControlState(nextState);
  if (type === "domain") {
    try {
      await syncRuleRemote("allowlist", nextRule);
      const currentState = await getControlState();
      await saveControlState({
        ...currentState,
        allowRules: currentState.allowRules.map((rule) => (
          rule.id === nextRule.id ? { ...rule, source: "remote" } : rule
        ))
      });
    } catch (error) {
      console.warn("Allowlist sync skipped:", error.message || error);
    }
  }

  return savedState;
}

export async function addBlockRule(type, value) {
  const user = await getSessionUser();
  const controlState = await getControlState();
  const nextRule = type === "domain"
    ? makeDomainRule(value, null, user ? "remote" : "local")
    : buildRule(type, value, user ? "remote" : "local");

  if (user) {
    console.info("[PhishGuard] Saving block rule to account mode:", { type: nextRule.type, value: nextRule.value });
    await syncRuleRemote("blocklist", nextRule);
    return hydrateRemoteControlsToLocal();
  }

  const nextState = {
    ...controlState,
    blockRules: [nextRule, ...controlState.blockRules.filter((rule) => !(rule.type === nextRule.type && rule.value === nextRule.value))]
  };

  return saveControlState(nextState);
}

export async function removeRule(kind, ruleId) {
  const controlState = await getControlState();
  const key = kind === "allow" ? "allowRules" : "blockRules";
  const rules = controlState[key];
  const targetRule = rules.find((rule) => rule.id === ruleId);
  const nextState = {
    ...controlState,
    [key]: rules.filter((rule) => rule.id !== ruleId)
  };

  const savedState = await saveControlState(nextState);
  if (targetRule?.source === "remote" || (kind === "allow" && targetRule?.type === "domain")) {
    try {
      await removeRuleRemote(kind === "allow" ? "allowlist" : "blocklist", targetRule);
    } catch (error) {
      console.warn("Remote rule removal skipped:", error.message || error);
    }
  }

  return savedState;
}

export async function addTemporaryAllow(url, minutes = TEMP_ALLOW_MINUTES) {
  const controlState = await getControlState();
  const expiresAt = new Date(Date.now() + minutes * 60 * 1000).toISOString();
  const nextState = {
    ...controlState,
    temporaryAllows: [
      {
        id: crypto.randomUUID(),
        type: "url",
        value: normalizeUrl(url),
        expiresAt,
        createdAt: new Date().toISOString()
      },
      ...controlState.temporaryAllows.filter((entry) => normalizeUrl(entry.value) !== normalizeUrl(url))
    ]
  };
  return saveControlState(nextState);
}

export async function clearTemporaryAllows() {
  const controlState = await getControlState();
  return saveControlState({ ...controlState, temporaryAllows: [] });
}

export async function hydrateRemoteControlsToLocal() {
  const user = await getSessionUser();
  if (!user) return getControlState();

  const supabase = getSupabaseClient();
  let allowResult;
  let blockResult;

  try {
    [allowResult, blockResult] = await Promise.all([
      supabase.from("allowlist").select("id, domain, created_at").eq("user_id", user.id).order("created_at", { ascending: false }),
      supabase.from("blocklist").select("id, domain, rule_type, rule_value, created_at").eq("user_id", user.id).order("created_at", { ascending: false })
    ]);
  } catch (error) {
    console.warn("Remote control hydration skipped:", error.message || error);
    return getControlState();
  }

  if (allowResult.error || blockResult.error) {
    console.warn("Remote control hydration skipped:", allowResult.error?.message || blockResult.error?.message);
    return getControlState();
  }

  const currentState = await getControlState();
  const localAllowRules = currentState.allowRules.filter((rule) => rule.source !== "remote");
  const localBlockRules = [];

  const nextState = {
    ...currentState,
    allowRules: dedupeRules([
      ...localAllowRules,
      ...(allowResult.data || []).map((row) => ({
        ...makeDomainRule(row.domain, row.id, "remote"),
        createdAt: row.created_at || new Date().toISOString()
      }))
    ]),
    blockRules: dedupeRules([
      ...localBlockRules,
      ...(blockResult.data || []).map((row) => ({
        id: row.id || crypto.randomUUID(),
        type: row.rule_type || "domain",
        value: String(row.rule_value || row.domain || "").trim().toLowerCase(),
        source: "remote",
        remoteId: row.id || null,
        createdAt: row.created_at || new Date().toISOString()
      }))
    ])
  };

  return saveControlState(nextState);
}

function dedupeRules(rules = []) {
  const seen = new Set();
  return rules.filter((rule) => {
    const key = `${rule.type}:${rule.value}:${rule.source}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export async function resolveControlDecision(url) {
  const controlState = await getControlState();
  const normalizedUrl = normalizeUrl(url);
  const hostname = getBaseDomain(url);

  for (const tempAllow of controlState.temporaryAllows) {
    if (normalizeUrl(tempAllow.value) === normalizedUrl) {
      return { decision: "allow", reason: "Temporary allow active", rule: tempAllow };
    }
  }

  for (const rule of controlState.allowRules) {
    if (matchesRule(url, rule)) {
      return { decision: "allow", reason: "Matched allowlist rule", rule };
    }
  }

  for (const rule of controlState.blockRules) {
    if (matchesRule(url, rule)) {
      return {
        decision: "block",
        reason: rule.type === "suffix" ? `Blocked suffix ${rule.value}` : "Matched block rule",
        rule
      };
    }
  }

  if (hostname.endsWith(".xyz")) {
    const xyzRule = controlState.blockRules.find((rule) => rule.type === "suffix" && rule.value === ".xyz");
    if (xyzRule) {
      return { decision: "block", reason: "Domain suffix blocked", rule: xyzRule };
    }
  }

  return { decision: "scan", reason: "No local control rule matched" };
}
