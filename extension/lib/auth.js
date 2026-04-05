import { getAuthRedirectUrl } from "./config.js";
import { DEFAULT_CONTROL_RULES, DEFAULT_SETTINGS, STORAGE_KEYS } from "./constants.js";
import { hydrateRemoteControlsToLocal } from "./controls.js";
import { hydrateRemoteSettingsToLocal } from "./settings-store.js";
import { getValue, removeLocal, setLocal, setValue } from "./storage.js";
import { ensureSupabaseSession, getSupabaseClient } from "./supabase-client.js";

async function cacheSessionMetadata(session) {
  if (!session?.user) {
    await setValue(STORAGE_KEYS.authCache, null);
    return null;
  }

  const metadata = {
    userId: session.user.id,
    email: session.user.email,
    displayName: session.user.user_metadata?.display_name || session.user.user_metadata?.full_name || "",
    provider: session.user.app_metadata?.provider || "email",
    expiresAt: session.expires_at || null
  };

  await setValue(STORAGE_KEYS.authCache, metadata);
  return metadata;
}

function isSchemaTableError(error, tableName) {
  const message = String(error?.message || "");
  const details = String(error?.details || "");
  const hint = String(error?.hint || "");
  const code = String(error?.code || "");
  return message.includes(`Could not find the table 'public.${tableName}'`) ||
    message.includes(`relation "public.${tableName}" does not exist`) ||
    details.includes(`public.${tableName}`) ||
    hint.includes(`public.${tableName}`) ||
    (code === "42P01" && message.includes(tableName)) ||
    (code === "PGRST205" && message.includes(tableName));
}

function isAnyKnownSchemaError(error, tableNames = []) {
  return tableNames.some((tableName) => isSchemaTableError(error, tableName));
}

async function runBootstrapTask(task, tableNames, label) {
  try {
    return await task();
  } catch (error) {
    if (isAnyKnownSchemaError(error, tableNames)) {
      console.warn(`Supabase bootstrap skipped for ${label}:`, error.message || error);
      return null;
    }

    console.warn(`Supabase bootstrap warning in ${label}:`, error.message || error);
    return null;
  }
}

async function bootstrapUser(user) {
  if (!user) return null;

  const supabase = getSupabaseClient();
  const displayName = user.user_metadata?.display_name || user.user_metadata?.full_name || null;

  await runBootstrapTask(async () => {
    const { error: profileError } = await supabase.from("profiles").upsert(
      {
        id: user.id,
        email: user.email,
        display_name: displayName,
        created_at: new Date().toISOString()
      },
      { onConflict: "id" }
    );

    if (profileError) throw profileError;
  }, ["profiles"], "profiles upsert");

  await runBootstrapTask(async () => {
    const { data: existingSettings, error: settingsLookupError } = await supabase
      .from("user_settings")
      .select("user_id")
      .eq("user_id", user.id)
      .maybeSingle();

    if (settingsLookupError) throw settingsLookupError;

    if (!existingSettings) {
      const { error: settingsInsertError } = await supabase.from("user_settings").insert({
        user_id: user.id,
        auto_block_enabled: DEFAULT_SETTINGS.autoBlockEnabled,
        auto_block_phishing: DEFAULT_SETTINGS.autoBlockPhishing,
        risk_threshold: DEFAULT_SETTINGS.riskThreshold,
        scan_mode: DEFAULT_SETTINGS.scanMode,
        security_mode: DEFAULT_SETTINGS.securityMode,
        updated_at: new Date().toISOString()
      });

      if (settingsInsertError) throw settingsInsertError;
    }
  }, ["user_settings"], "settings bootstrap");

  await runBootstrapTask(
    () => hydrateRemoteSettingsToLocal(),
    ["user_settings"],
    "settings hydration"
  );
  await runBootstrapTask(
    () => hydrateRemoteControlsToLocal(),
    ["allowlist", "blocklist"],
    "control hydration"
  );

  return user;
}

async function clearUserScopedCaches() {
  const existingControls = await getValue(STORAGE_KEYS.controls, DEFAULT_CONTROL_RULES);
  const sanitizedControls = {
    allowRules: (existingControls.allowRules || []).filter((rule) => rule.source !== "remote"),
    blockRules: (existingControls.blockRules || []).filter((rule) => rule.source !== "remote"),
    temporaryAllows: existingControls.temporaryAllows || []
  };

  await setLocal({
    [STORAGE_KEYS.authCache]: null,
    [STORAGE_KEYS.controls]: sanitizedControls
  });
}

export async function getSession() {
  return ensureSupabaseSession();
}

export async function restoreSessionContext() {
  const session = await getSession();
  await cacheSessionMetadata(session);

  if (session?.user) {
    await bootstrapUser(session.user);
  } else {
    await clearUserScopedCaches();
  }

  return session;
}

export async function getCachedAuth() {
  return getValue(STORAGE_KEYS.authCache, null);
}

export async function signUpWithEmail(email, password, displayName) {
  const supabase = getSupabaseClient();
  const normalizedDisplayName = String(displayName || "").trim() || email.split("@")[0];
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: {
      data: {
        display_name: normalizedDisplayName
      },
      emailRedirectTo: getAuthRedirectUrl()
    }
  });

  if (error) throw error;

  if (data.session?.user) {
    await cacheSessionMetadata(data.session);
    await bootstrapUser(data.session.user);
  } else if (data.user) {
    await runBootstrapTask(async () => {
      const { error: profileError } = await supabase.from("profiles").upsert(
        {
          id: data.user.id,
          email: data.user.email,
          display_name: normalizedDisplayName,
          created_at: new Date().toISOString()
        },
        { onConflict: "id" }
      );

      if (profileError) throw profileError;
    }, ["profiles"], "signup profile bootstrap");
  }

  return data;
}

export async function signInWithEmail(email, password) {
  const supabase = getSupabaseClient();
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) throw error;

  await cacheSessionMetadata(data.session);
  await bootstrapUser(data.session?.user);
  return data;
}

export async function signInWithGoogle() {
  const supabase = getSupabaseClient();
  const redirectTo = chrome.identity.getRedirectURL("supabase-callback");
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: "google",
    options: {
      redirectTo,
      queryParams: {
        prompt: "select_account"
      },
      skipBrowserRedirect: true
    }
  });

  if (error) throw error;
  if (!data?.url) throw new Error("Supabase did not return a Google sign-in URL.");

  const responseUrl = await chrome.identity.launchWebAuthFlow({
    url: data.url,
    interactive: true
  });

  if (!responseUrl) {
    throw new Error("Google sign-in did not return a callback URL.");
  }

  const session = await exchangeCodeForSession(responseUrl);
  if (!session) {
    throw new Error("Google sign-in did not produce a session.");
  }

  return session;
}

export async function exchangeCodeForSession(urlString) {
  const supabase = getSupabaseClient();
  const currentUrl = new URL(urlString);
  const authCode = currentUrl.searchParams.get("code");
  const errorMessage = currentUrl.searchParams.get("error_description");

  if (errorMessage) {
    throw new Error(errorMessage);
  }

  if (authCode) {
    const { data, error } = await supabase.auth.exchangeCodeForSession(authCode);
    if (error) throw error;

    await cacheSessionMetadata(data.session);
    await bootstrapUser(data.session?.user);
    return data.session;
  }

  const hashParams = new URLSearchParams(currentUrl.hash.replace(/^#/, ""));
  const accessToken = hashParams.get("access_token");
  const refreshToken = hashParams.get("refresh_token");

  if (accessToken && refreshToken) {
    const { data, error } = await supabase.auth.setSession({
      access_token: accessToken,
      refresh_token: refreshToken
    });
    if (error) throw error;

    await cacheSessionMetadata(data.session);
    await bootstrapUser(data.session?.user);
    return data.session;
  }

  return null;
}

export async function signOutUser() {
  const supabase = getSupabaseClient();
  await removeLocal(STORAGE_KEYS.supabaseSession);
  try {
    const { error } = await supabase.auth.signOut({ scope: "local" });
    if (error) {
      console.warn("Supabase sign-out warning:", error.message || error);
    }
  } catch (error) {
    console.warn("Supabase sign-out threw an error, continuing with local cleanup:", error.message || error);
  }
  await clearUserScopedCaches();
}

export function registerAuthStateListener(callback) {
  const supabase = getSupabaseClient();
  return supabase.auth.onAuthStateChange((_event, session) => {
    setTimeout(async () => {
      try {
        if (session?.user) {
          await cacheSessionMetadata(session);
          await bootstrapUser(session.user);
        } else {
          await clearUserScopedCaches();
        }

        if (callback) {
          callback(session);
        }
      } catch (error) {
        console.warn("Auth state listener update skipped:", error.message || error);
      }
    }, 0);
  });
}
