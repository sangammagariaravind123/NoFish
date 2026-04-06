import { createClient } from "../vendor/supabase.js";
import { SUPABASE_ANON_KEY, SUPABASE_URL } from "./config.js";
import { STORAGE_KEYS } from "./constants.js";
import { getValue, removeLocal, setValue } from "./storage.js";

const authStorage = {
  async getItem(key) {
    const value = await getValue(key, null);
    return value ?? null;
  },
  async setItem(key, value) {
    await setValue(key, value);
  },
  async removeItem(key) {
    await removeLocal(key);
  }
};

let supabaseClient;
let sessionHydrationPromise = null;

function isLockContentionError(error) {
  const message = String(error?.message || error || "");
  return message.includes('Lock "lock:phishguard.supabase.session"');
}

function waitFor(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export function getSupabaseClient() {
  if (!supabaseClient) {
    supabaseClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      auth: {
        autoRefreshToken: true,
        persistSession: true,
        detectSessionInUrl: false,
        flowType: "pkce",
        storageKey: STORAGE_KEYS.supabaseSession,
        storage: authStorage
      },
      global: {
        headers: {
          "X-Client-Info": "phishguard-extension"
        }
      }
    });
  }

  return supabaseClient;
}

export async function ensureSupabaseSession() {
  if (sessionHydrationPromise) {
    return sessionHydrationPromise;
  }

  const supabase = getSupabaseClient();
  sessionHydrationPromise = (async () => {
    try {
      for (let attempt = 0; attempt < 6; attempt += 1) {
        const { data, error } = await supabase.auth.getSession();
        if (error && !isLockContentionError(error)) throw error;
        if (data?.session) {
          return data.session;
        }

        if (attempt < 5) {
          await waitFor(120);
        }
      }

      return null;
    } finally {
      sessionHydrationPromise = null;
    }
  })();

  return sessionHydrationPromise;
}
