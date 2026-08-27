// Service Worker configuration for Digital Safety AI Platform

const BACKEND_URL = 'http://localhost:5000/api/scan';

chrome.runtime.onInstalled.addListener(() => {
  console.log('Digital Safety AI Platform Extension installed/updated.');
  // Initialize default extension storage settings
  chrome.storage.local.set({
    settings: {
      autoScanGmail: true,
      autoScanLinkedIn: true,
      riskThreshold: 50
    },
    scanStats: {
      totalScans: 0,
      threatsDetected: 0
    }
  }, () => {
    console.log('Default storage configuration initialized.');
  });
});

// Listener for messages from Content Scripts or Popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Background received message:', request);

  if (request.action === 'scanText') {
    // Perform scan by making a fetch request to the backend API
    scanTextContent(request.payload)
      .then(result => {
        // Update stats in storage if threat is detected
        updateScanStats(result.success && result.data && result.data.riskLevel !== 'LOW');
        sendResponse({ success: true, data: result });
      })
      .catch(error => {
        console.error('Scan request failed:', error);
        sendResponse({ success: false, error: error.message });
      });

    // Return true to indicate we will reply asynchronously
    return true;
  }

  if (request.action === 'getStats') {
    chrome.storage.local.get('scanStats', (result) => {
      sendResponse({ success: true, stats: result.scanStats });
    });
    return true;
  }
});

/**
 * Sends text payload to Express backend scan endpoint
 */
async function scanTextContent({ text, source, sender = '' }) {
  const response = await fetch(BACKEND_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    // sender is the raw email address extracted from the DOM (e.g. "noreply@sbl.com.np").
    // The backend injects it directly into the Gemini system prompt for domain verification.
    body: JSON.stringify({ text, source, sender })
  });

  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }

  return await response.json();
}

/**
 * Increments scan count and threats count in chrome local storage
 */
function updateScanStats(isThreat) {
  chrome.storage.local.get('scanStats', (result) => {
    const stats = result.scanStats || { totalScans: 0, threatsDetected: 0 };
    stats.totalScans += 1;
    if (isThreat) {
      stats.threatsDetected += 1;
    }
    chrome.storage.local.set({ scanStats: stats }, () => {
      console.log('Scan stats updated in storage:', stats);
    });
  });
}
