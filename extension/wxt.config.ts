import { defineConfig } from 'wxt';

// See https://wxt.dev/api/config.html
export default defineConfig({
  manifest: {
    manifest_version: 3,
    name: 'DigiSafe Threat Detector',
    version: '1.1.0',
    permissions: ['storage', 'activeTab', 'scripting', 'identity', 'tabs'],
    host_permissions: [
      'http://localhost:5000/*',
      'http://localhost:3000/*',
      'http://127.0.0.1:3000/*',
      'http://127.0.0.1:5000/*',
      'https://abmtdxixfbryubdapgow.supabase.co/*',
      '*://mail.google.com/*',
      '*://*.linkedin.com/*',
      'https://web.whatsapp.com/*'
    ],
  },
  srcDir: 'src',
});
