/**
 * API client helper to interact with the Digital Safety AI Platform background worker
 */
export const DigitalSafetyAPI = {
  /**
   * Scans a string of text against the backend API via background proxy
   * @param {string} text - The content text to analyze
   * @param {string} source - Where the text came from (e.g. 'gmail', 'linkedin')
   * @returns {Promise<Object>} The API JSON response containing threat status
   */
  async scanText(text, source) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(
        {
          action: 'scanText',
          payload: { text, source }
        },
        (response) => {
          if (chrome.runtime.lastError) {
            return reject(new Error(chrome.runtime.lastError.message));
          }
          if (!response || !response.success) {
            return reject(new Error(response?.error || 'Unknown error occurred during scan'));
          }
          resolve(response.data);
        }
      );
    });
  },

  /**
   * Fetches local statistics from extension storage
   * @returns {Promise<Object>} The total scan count and threats detected count
   */
  async getScanStats() {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ action: 'getStats' }, (response) => {
        if (chrome.runtime.lastError) {
          return reject(new Error(chrome.runtime.lastError.message));
        }
        if (!response || !response.success) {
          return reject(new Error('Failed to retrieve statistics'));
        }
        resolve(response.stats);
      });
    });
  }
};
