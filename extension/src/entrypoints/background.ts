import { defineBackground } from 'wxt/sandbox';
import { supabase } from '@/utils/supabase';

export default defineBackground(() => {
  console.log('DigiSafe Background Worker initialized.');

  browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'SCAN_REQUEST') {
      sendScanPayload(message.payload)
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

  async function sendScanPayload(payload: any) {
    try {
      const { data: { session } } = await supabase.auth.getSession();
      const token = session?.access_token;
      const email = session?.user?.email;

      const bodyPayload = { ...payload, email };

      const response = await fetch('http://localhost:5000/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(bodyPayload),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('[DigiSafe Background Worker] Scan Failure:', error);
      throw error;
    }
  }
});
