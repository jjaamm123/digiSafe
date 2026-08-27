// Digital Safety AI Platform - Popup Dashboard Controller

document.addEventListener('DOMContentLoaded', async () => {
  console.log('[Digital Safety AI] Popup loaded.');

  const totalScansEl = document.getElementById('stat-total-scans');
  const threatsDetectedEl = document.getElementById('stat-threats-detected');
  const toggleGmail = document.getElementById('toggle-gmail');
  const toggleLinkedIn = document.getElementById('toggle-linkedin');
  const engineStatusEl = document.getElementById('engine-status');
  const apiTestBtn = document.getElementById('api-test-btn');

  // 1. Sync stats and settings from local storage
  chrome.storage.local.get(['settings', 'scanStats'], (result) => {
    // Populate Statistics
    const stats = result.scanStats || { totalScans: 0, threatsDetected: 0 };
    totalScansEl.textContent = stats.totalScans;
    threatsDetectedEl.textContent = stats.threatsDetected;

    // Populate Settings checkboxes
    const settings = result.settings || { autoScanGmail: true, autoScanLinkedIn: true };
    toggleGmail.checked = settings.autoScanGmail;
    toggleLinkedIn.checked = settings.autoScanLinkedIn;
  });

  // 2. Toggle listener for Gmail
  toggleGmail.addEventListener('change', () => {
    chrome.storage.local.get('settings', (result) => {
      const currentSettings = result.settings || {};
      currentSettings.autoScanGmail = toggleGmail.checked;
      chrome.storage.local.set({ settings: currentSettings }, () => {
        console.log('Gmail scanning configuration updated:', toggleGmail.checked);
      });
    });
  });

  // 3. Toggle listener for LinkedIn
  toggleLinkedIn.addEventListener('change', () => {
    chrome.storage.local.get('settings', (result) => {
      const currentSettings = result.settings || {};
      currentSettings.autoScanLinkedIn = toggleLinkedIn.checked;
      chrome.storage.local.set({ settings: currentSettings }, () => {
        console.log('LinkedIn scanning configuration updated:', toggleLinkedIn.checked);
      });
    });
  });

  // 4. Perform health check on Express safety engine backend
  async function checkBackendConnection() {
    try {
      engineStatusEl.textContent = 'Pinging...';
      engineStatusEl.className = 'connection-value';

      const response = await fetch('http://localhost:5000/health');
      if (response.ok) {
        engineStatusEl.textContent = 'CONNECTED';
        engineStatusEl.classList.add('connected');
      } else {
        throw new Error('Server returned unhealthy state');
      }
    } catch (error) {
      console.warn('[Digital Safety AI] Connection to backend offline:', error);
      engineStatusEl.textContent = 'OFFLINE';
      engineStatusEl.classList.add('disconnected');
    }
  }

  // Initial connection scan
  await checkBackendConnection();

  // 5. Test button capability
  apiTestBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    console.log('[Digital Safety AI] Running manual connection test...');
    await checkBackendConnection();
  });
});
