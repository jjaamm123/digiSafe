import { defineConfig } from 'wxt';

// See https://wxt.dev/api/config.html
export default defineConfig({
  manifest: {
    manifest_version: 3,
    name: 'DigiSafe Threat Detector',
    version: '1.2.0',
    permissions: ['storage', 'activeTab', 'scripting', 'identity', 'tabs'],
    host_permissions: [
      'http://localhost:3000/*',
      'http://127.0.0.1:3000/*',
      'https://*.supabase.co/*',
      '*://mail.google.com/*',
      '*://*.linkedin.com/*',
      'https://web.whatsapp.com/*',
      'https://cdn.jsdelivr.net/*',
      'https://huggingface.co/*',
      'https://hf.co/*'
    ],
    content_security_policy: {
      extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'",
    },
  },
  srcDir: 'src',
});
