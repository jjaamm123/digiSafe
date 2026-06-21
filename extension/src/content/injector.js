/**
 * Digital Safety AI Platform - DOM Injector Helper
 * 
 * This module is responsible for injecting the badge and handling state transitions.
 * In Phase 2, this modular javascript can be replaced by mounting a React root
 * to the container element:
 *   const root = ReactDOM.createRoot(container);
 *   root.render(<BadgeOverlay text={text} source={source} />);
 */

window.DigitalSafetyInjector = {
  /**
   * Injects a scan badge overlay into a specific target DOM node
   * @param {HTMLElement} anchorElement - The DOM node to attach the badge to
   * @param {string} textToScan - The text extract to send to the backend
   * @param {string} source - Source website identifier ('gmail' or 'linkedin')
   */
  injectBadge(anchorElement, textToScan, source) {
    if (!anchorElement) return;

    // Prevent double injection
    if (anchorElement.querySelector('.dsa-badge-container')) {
      return;
    }

    // 1. Create the container node (This will act as the React mounting root in Phase 2)
    const container = document.createElement('div');
    container.className = 'dsa-badge-container';

    // 2. Build the basic badge HTML trigger
    container.innerHTML = `
      <button class="dsa-scan-button" title="Scan content safety with Digital Safety AI">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 4px;">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        <span>Scan Security</span>
      </button>
    `;

    // 3. Append to target DOM
    anchorElement.appendChild(container);

    const button = container.querySelector('.dsa-scan-button');

    // 4. Attach click listener for scanning action
    button.addEventListener('click', async (e) => {
      e.stopPropagation();
      e.preventDefault();

      // Check if already scanning
      if (button.disabled) return;

      // Update UI to loading state
      const buttonText = button.querySelector('span');
      const originalHtml = button.innerHTML;
      button.disabled = true;
      button.innerHTML = `<span class="dsa-spinner"></span> <span>Analyzing...</span>`;

      // Remove any existing result cards
      const existingCard = container.querySelector('.dsa-result-card');
      if (existingCard) existingCard.remove();

      try {
        // Dispatch scan request using Chrome Runtime messaging to bypass CORS/CSP
        const response = await new Promise((resolve, reject) => {
          chrome.runtime.sendMessage(
            {
              action: 'scanText',
              payload: { text: textToScan, source: source }
            },
            (res) => {
              if (chrome.runtime.lastError) {
                reject(new Error(chrome.runtime.lastError.message));
              } else if (!res || !res.success) {
                reject(new Error(res?.error || 'Server error, check server logs'));
              } else {
                resolve(res.data);
              }
            }
          );
        });

        // Scan Success - Restore button and show results card
        button.disabled = false;
        button.innerHTML = originalHtml;
        this.renderResultCard(container, response.data);

      } catch (error) {
        console.error('[Digital Safety] Scan failed:', error);
        // Scan Error state
        button.disabled = false;
        button.innerHTML = originalHtml;
        this.renderErrorCard(container, error.message);
      }
    });
  },

  /**
   * Renders the glassmorphic threat summary card below the button
   */
  renderResultCard(container, analysis) {
    const card = document.createElement('div');
    card.className = 'dsa-result-card';

    const riskClass = `dsa-risk-${analysis.riskLevel.toLowerCase()}`;
    const indicatorsHtml = analysis.indicators.length > 0
      ? `<ul class="dsa-indicators-list">
          ${analysis.indicators.map(ind => `<li class="dsa-indicator-item">${ind}</li>`).join('')}
         </ul>`
      : '<p style="font-size: 11px; color: #a3e635; margin-top: 4px; padding-left: 4px;">✓ Safe content environment</p>';

    card.innerHTML = `
      <div class="dsa-card-header">
        <span class="dsa-title">Threat Assessment</span>
        <button class="dsa-close-btn">&times;</button>
      </div>
      
      <div class="dsa-metric">
        <span>Risk Category:</span>
        <span class="dsa-risk-badge ${riskClass}">${analysis.classification}</span>
      </div>
      
      <div class="dsa-metric">
        <span>Risk Score:</span>
        <span class="dsa-metric-val">${analysis.riskScore}%</span>
      </div>

      <div style="margin-top: 6px;">
        <span style="font-size: 11px; font-weight: bold; color: #94a3b8;">Key Indicators:</span>
        ${indicatorsHtml}
      </div>

      <div style="font-size: 9px; color: #64748b; text-align: right; margin-top: 4px;">
        Scanned at: ${new Date(analysis.analyzedAt).toLocaleTimeString()}
      </div>
    `;

    // Attach close behavior
    card.querySelector('.dsa-close-btn').addEventListener('click', (e) => {
      e.stopPropagation();
      card.remove();
    });

    container.appendChild(card);
  },

  /**
   * Renders error feedback if communication fails
   */
  renderErrorCard(container, errorMsg) {
    const card = document.createElement('div');
    card.className = 'dsa-result-card';
    card.innerHTML = `
      <div class="dsa-card-header">
        <span class="dsa-title" style="color: #f87171;">Scan Failed</span>
        <button class="dsa-close-btn">&times;</button>
      </div>
      <p class="dsa-error-text">
        Unable to connect to the analysis engine. Ensure the backend server is running on http://localhost:5000.<br/>
        <span style="font-size: 9px; opacity: 0.8; word-break: break-all;">Error: ${errorMsg}</span>
      </p>
    `;

    card.querySelector('.dsa-close-btn').addEventListener('click', (e) => {
      e.stopPropagation();
      card.remove();
    });

    container.appendChild(card);
  }
};
