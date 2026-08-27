import { defineBackground } from 'wxt/sandbox';

export default defineBackground(() => {
  console.log('DigiSafe Background Worker initialized.');

  browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'SCAN_REQUEST') {
      handleScanWithFallback(message.payload)
        .then((data) => sendResponse({ success: true, data }))
        .catch((err) => {
          console.error('[DigiSafe Background Worker] Scan Failure:', err);
          sendResponse({ 
            success: false, 
            error: `${err.message || 'Failed to reach scan server'}. Ensure backend is running.` 
          });
        });
      return true; // Keep channel open for async response
    }
  });

  async function handleScanWithFallback(payload: { text: string; source: string }) {
    // Support both 3000 (Next.js) and 5000 (Express)
    const candidateUrls = [
      'http://localhost:3000/api/scan',
      'http://127.0.0.1:3000/api/scan',
      'http://localhost:5000/api/scan'
    ];

    let lastError: Error | null = null;

    for (const url of candidateUrls) {
      try {
        console.log(`[DigiSafe] Attempting scan request to: ${url}`);
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000);

        const response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          body: JSON.stringify(payload),
          signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const result = await response.json();
        console.log(`[DigiSafe] Scan successful via: ${url}`);
        return result;
      } catch (err: any) {
        console.warn(`[DigiSafe] Failed endpoint ${url}:`, err.message);
        lastError = err;
      }
    }

    throw lastError || new Error('All backend endpoints unreachable');
  }
});
