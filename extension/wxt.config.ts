import { defineConfig } from 'wxt';

// See https://wxt.dev/api/config.html
export default defineConfig({
  manifest: {
    manifest_version: 3,
    name: 'DigiSafe Threat Detector',
    version: '1.0.0',
    permissions: ['storage', 'activeTab', 'scripting'],
    host_permissions: [
      'https://mail.google.com/*',
      'https://*.linkedin.com/*',
      'http://localhost:3000/*',
      'http://localhost:5000/*',
      'http://127.0.0.1:3000/*',
      'http://127.0.0.1:5000/*'
    ],
  },
  srcDir: 'src',
});
