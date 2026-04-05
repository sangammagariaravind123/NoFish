import { DEFAULT_CONTROL_RULES, STORAGE_KEYS, TEMP_ALLOW_MINUTES } from "./constants.js";
import { getValue, setValue } from "./storage.js";
import { getSupabaseClient } from "./supabase-client.js";
import { getBaseDomain, makeDomainRule, matchesRule, normalizeUrl } from "./url-utils.js";

function normalizeRules(state = {}) {
  return {
    allowRules: Array.isArray(state.allowRules) ? state.allowRules : [],
    blockRules: Array.isArray(state.blockRules) ? state.blockRules : [],
    temporaryAllows: Array.isArray(state.temporaryAllows) ? state.temporaryAllows : []
  };
}

async function getSessionUser() {
  const supabase = getSupabaseClient();
  const { data } = await supabase.auth.getSession();
  return data.session?.user ?? null;
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

async function syncRuleRemote(table, value) {
  const user = await getSessionUser();
  if (!user) return null;

  const supabase = getSupabaseClient();
  const payload = {
    user_id: user.id,
    domain: value,
    created_at: new Date().toISOString()
  };

  const { error } = await supabase.from(table).upsert(payload, { onConflict: "user_id,domain" });
  if (error) throw error;
  return payload;
}

async function removeRuleRemote(table, value) {
  const user = await getSessionUser();
  if (!user) return;

  const supabase = getSupabaseClient();
  const { error } = await supabase
    .from(table)
    .delete()
    .eq("user_id", user.id)
    .eq("domain", value);

  if (error) throw error;
}

export async function addAllowRule(type, value) {
  const controlState = await getControlState();
  const nextRule = type === "domain" ? makeDomainRule(value) : buildRule(type, value);
  const nextState = {
    ...controlState,
    allowRules: [nextRule, ...controlState.allowRules.filter((rule) => !(rule.type === nextRule.type && rule.value === nextRule.value))]
  };

  const savedState = await saveControlState(nextState);
  if (type === "domain") {
    try {
      await syncRuleRemote("allowlist", nextRule.value);
    } catch (error) {
      console.warn("Allowlist sync skipped:", error.message || error);
    }
  }

  return savedState;
}

export async function addBlockRule(type, value) {
  const controlState = await getControlState();
  const nextRule = type === "domain" ? makeDomainRule(value) : buildRule(type, value);
  const nextState = {
    ...controlState,
    blockRules: [nextRule, ...controlState.blockRules.filter((rule) => !(rule.type === nextRule.type && rule.value === nextRule.value))]
  };

  const savedState = await saveControlState(nextState);
  if (type === "domain") {
    try {
      await syncRuleRemote("blocklist", nextRule.value);
    } catch (error) {
      console.warn("Blocklist sync skipped:", error.message || error);
    }
  }

  return savedState;
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
  if (targetRule?.type === "domain") {
    try {
      await removeRuleRemote(kind === "allow" ? "allowlist" : "blocklist", targetRule.value);
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
      supabase.from("blocklist").select("id, domain, created_at").eq("user_id", user.id).order("created_at", { ascending: false })
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
  const advancedAllowRules = currentState.allowRules.filter((rule) => rule.type !== "domain");
  const advancedBlockRules = currentState.blockRules.filter((rule) => rule.type !== "domain");

  const nextState = {
    ...currentState,
    allowRules: [
      ...advancedAllowRules,
      ...(allowResult.data || []).map((row) => ({
        ...makeDomainRule(row.domain, row.id, "remote"),
        createdAt: row.created_at || new Date().toISOString()
      }))
    ],
    blockRules: [
      ...advancedBlockRules,
      ...(blockResult.data || []).map((row) => ({
        ...makeDomainRule(row.domain, row.id, "remote"),
        createdAt: row.created_at || new Date().toISOString()
      }))
    ]
  };

  return saveControlState(nextState);
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
