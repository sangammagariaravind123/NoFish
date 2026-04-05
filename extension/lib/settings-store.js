import {
  DEFAULT_SETTINGS,
  DEFAULT_UI_STATE,
  SECURITY_MODE_PRESETS,
  STORAGE_KEYS
} from "./constants.js";
import { getValue, setLocal, setValue } from "./storage.js";
import { getSupabaseClient } from "./supabase-client.js";

function normalizeSettings(settings = {}) {
  return {
    ...DEFAULT_SETTINGS,
    autoBlockEnabled: settings.autoBlockEnabled ?? settings.auto_block_enabled ?? DEFAULT_SETTINGS.autoBlockEnabled,
    riskThreshold: Number(settings.riskThreshold ?? settings.risk_threshold ?? DEFAULT_SETTINGS.riskThreshold),
    scanMode: settings.scanMode ?? settings.scan_mode ?? DEFAULT_SETTINGS.scanMode,
    securityMode: settings.securityMode ?? settings.security_mode ?? DEFAULT_SETTINGS.securityMode
  };
}

export async function ensureLocalSettings() {
  const settings = normalizeSettings(await getValue(STORAGE_KEYS.settings, DEFAULT_SETTINGS));
  const uiState = { ...DEFAULT_UI_STATE, ...(await getValue(STORAGE_KEYS.uiState, DEFAULT_UI_STATE)) };
  await setLocal({
    [STORAGE_KEYS.settings]: settings,
    [STORAGE_KEYS.uiState]: uiState
  });
  return { settings, uiState };
}

export async function getSettings() {
  const { settings } = await ensureLocalSettings();
  return settings;
}

export async function getUiState() {
  const { uiState } = await ensureLocalSettings();
  return uiState;
}

export async function setUiState(partialState) {
  const currentState = await getUiState();
  const nextState = { ...currentState, ...partialState };
  await setValue(STORAGE_KEYS.uiState, nextState);
  return nextState;
}

export async function saveSettings(partialSettings, options = {}) {
  const currentSettings = await getSettings();
  const nextSettings = normalizeSettings({ ...currentSettings, ...partialSettings });
  await setValue(STORAGE_KEYS.settings, nextSettings);

  if (options.syncRemote !== false) {
    await saveSettingsRemote(nextSettings);
  }

  return nextSettings;
}

export async function applySecurityPreset(mode) {
  const preset = SECURITY_MODE_PRESETS[mode];
  if (!preset) {
    return getSettings();
  }

  return saveSettings({
    securityMode: mode,
    autoBlockEnabled: preset.autoBlockEnabled,
    riskThreshold: preset.riskThreshold,
    scanMode: preset.scanMode
  });
}

export async function saveSettingsRemote(settings) {
  const supabase = getSupabaseClient();
  const { data: sessionData } = await supabase.auth.getSession();
  const user = sessionData.session?.user;
  if (!user) return null;

  const payload = {
    user_id: user.id,
    auto_block_enabled: settings.autoBlockEnabled,
    risk_threshold: settings.riskThreshold,
    scan_mode: settings.scanMode,
    security_mode: settings.securityMode,
    updated_at: new Date().toISOString()
  };

  const { error } = await supabase.from("user_settings").upsert(payload, {
    onConflict: "user_id"
  });

  if (error) throw error;
  return payload;
}

export async function hydrateRemoteSettingsToLocal() {
  const supabase = getSupabaseClient();
  const { data: sessionData } = await supabase.auth.getSession();
  const user = sessionData.session?.user;
  if (!user) {
    return getSettings();
  }

  const { data, error } = await supabase
    .from("user_settings")
    .select("*")
    .eq("user_id", user.id)
    .maybeSingle();

  if (error) throw error;

  if (!data) {
    return saveSettings(DEFAULT_SETTINGS);
  }

  const nextSettings = normalizeSettings(data);
  await setValue(STORAGE_KEYS.settings, nextSettings);
  return nextSettings;
}
