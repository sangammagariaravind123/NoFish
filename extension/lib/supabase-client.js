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
