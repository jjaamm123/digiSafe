import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.WXT_SUPABASE_URL || '';
const supabaseAnonKey = import.meta.env.WXT_SUPABASE_ANON_KEY || '';

if (!supabaseUrl || !supabaseAnonKey) {
  console.warn(
    '[DigiSafe] Supabase URL or Anon Key is missing. Ensure .env has WXT_SUPABASE_URL and WXT_SUPABASE_ANON_KEY set and restart the build.'
  );
}

// Provide a dummy fallback URL so createClient does not crash the service worker at boot
export const supabase = createClient(
  supabaseUrl || 'https://placeholder.supabase.co',
  supabaseAnonKey || 'placeholder-key',
  {
    auth: {
      storage: {
        getItem: async (key: string) => {
          try {
            const res = await chrome.storage.local.get(key);
            return res[key] || null;
          } catch {
            return null;
          }
        },
        setItem: async (key: string, value: string) => {
          try {
            await chrome.storage.local.set({ [key]: value });
          } catch (e) {
            console.error('Failed to set storage:', e);
          }
        },
        removeItem: async (key: string) => {
          try {
            await chrome.storage.local.remove(key);
          } catch (e) {
            console.error('Failed to remove storage:', e);
          }
        },
      },
      autoRefreshToken: true,
      persistSession: true,
      detectSessionInUrl: false,
    },
  }
);
