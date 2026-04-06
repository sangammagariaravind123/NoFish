export const SUPABASE_URL = "https://wyefsxtndxbcdzybuzog.supabase.co";
export const SUPABASE_ANON_KEY = "sb_publishable_Pq-4TCCa1ENoyuLWh2oRCA_TGmJhfet";

export function getAuthRedirectUrl() {
  return chrome.runtime.getURL("auth-callback.html");
}
