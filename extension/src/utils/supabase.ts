import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.WXT_SUPABASE_URL;
const supabaseAnonKey = import.meta.env.WXT_SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseUrl.startsWith('https://')) {
  console.error(
    '[DigiSafe] FATAL: WXT_SUPABASE_URL is missing or malformed in .env. ' +
    `Received: "${supabaseUrl}". Auth requests will fail. ` +
    'Ensure .env has WXT_SUPABASE_URL=https://your-project.supabase.co and restart the build.'
  );
}

if (!supabaseAnonKey || supabaseAnonKey.length < 20) {
  console.error(
    '[DigiSafe] FATAL: WXT_SUPABASE_ANON_KEY is missing or too short in .env. ' +
    'Auth requests will fail. Ensure .env has WXT_SUPABASE_ANON_KEY set and restart the build.'
  );
}

// Provide a dummy fallback URL so createClient does not crash the service worker at boot
export const supabase = createClient(
  supabaseUrl || 'https://placeholder.supabase.co',
  supabaseAnonKey || 'placeholder-key',
  {
    auth: {
      storage: {
        getItem: async (key: string): Promise<string | null> => {
          try {
            if (typeof chrome !== 'undefined' && chrome.storage?.local) {
              const res = await chrome.storage.local.get(key);
              return res[key] || null;
            }
            if (typeof localStorage !== 'undefined') {
              return localStorage.getItem(key);
            }
            return null;
          } catch {
            return null;
          }
        },
        setItem: async (key: string, value: string): Promise<void> => {
          try {
            if (typeof chrome !== 'undefined' && chrome.storage?.local) {
              await chrome.storage.local.set({ [key]: value });
            } else if (typeof localStorage !== 'undefined') {
              localStorage.setItem(key, value);
            }
          } catch (e) {
            console.warn('Failed to set storage:', e);
          }
        },
        removeItem: async (key: string): Promise<void> => {
          try {
            if (typeof chrome !== 'undefined' && chrome.storage?.local) {
              await chrome.storage.local.remove(key);
            } else if (typeof localStorage !== 'undefined') {
              localStorage.removeItem(key);
            }
          } catch (e) {
            console.warn('Failed to remove storage:', e);
          }
        },
      },
      autoRefreshToken: true,
      persistSession: true,
      detectSessionInUrl: false,
    },
  }
);
