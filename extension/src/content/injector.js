/**
 * Digital Safety AI Platform - DOM Injector Helper
 *
 * This module is responsible for injecting the badge and handling state transitions.
 * In Phase 2, this modular javascript can be replaced by mounting a React root
 * to the container element:
 *   const root = ReactDOM.createRoot(container);
 *   root.render(<BadgeOverlay text={text} source={source} sender={sender} />);
 */

window.DigitalSafetyInjector = {
  /**
   * Injects a scan badge overlay into a specific target DOM node.
   * @param {HTMLElement} anchorElement - The DOM node to attach the badge to
   * @param {string} textToScan        - The extracted email/post body text
   * @param {string} source            - Site identifier: 'gmail' or 'linkedin'
   * @param {string} [sender='']       - Raw sender email address extracted from the DOM header
   *                                     (e.g. "noreply@sbl.com.np"). Empty string if unavailable.
   */
  injectBadge(anchorElement, textToScan, source, sender = '') {
    if (!anchorElement) return;

    // Prevent double injection
    if (anchorElement.querySelector('.dsa-badge-container')) {
      return;
    }

    // 1. Create the container node (React mounting root in Phase 2)
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

      if (button.disabled) return;

      // Update UI to loading state
      const originalHtml = button.innerHTML;
      button.disabled = true;
      button.innerHTML = `<span class="dsa-spinner"></span> <span>Analyzing...</span>`;

      // Remove any existing result cards
      const existingCard = container.querySelector('.dsa-result-card');
      if (existingCard) existingCard.remove();

      try {
        // Dispatch scan request through the background service worker (bypasses CORS/CSP).
        // The payload now includes `sender` so the backend can inject it directly into
        // the Gemini system prompt for authoritative domain verification.
        const response = await new Promise((resolve, reject) => {
          chrome.runtime.sendMessage(
            {
              action: 'scanText',
              payload: {
                text:   textToScan,
                source: source,
                sender: sender      // ← raw email address e.g. "noreply@sbl.com.np"
              }
            },
            (res) => {
              if (chrome.runtime.lastError) {
                reject(new Error(chrome.runtime.lastError.message));
              } else if (!res || !res.success) {
                reject(new Error(res?.error || 'Server error — check backend logs'));
              } else {
                resolve(res.data);
              }
            }
          );
        });

        // Scan Success — restore button and render the result card
        button.disabled = false;
        button.innerHTML = originalHtml;
        this.renderResultCard(container, response.data);

      } catch (error) {
        console.error('[Digital Safety] Scan failed:', error);
        button.disabled = false;
        button.innerHTML = originalHtml;
        this.renderErrorCard(container, error.message);
      }
    });
  },

  /**
   * Renders the glassmorphic threat summary card below the button,
   * including the collapsible Extended View with flaggedPhrases warning pills.
   * @param {HTMLElement} container - The badge container to append the card to
   * @param {Object}      analysis  - The analysis result object from the backend
   */
  renderResultCard(container, analysis) {
    const card = document.createElement('div');
    card.className = 'dsa-result-card';

    const riskClass = `dsa-risk-${analysis.riskLevel.toLowerCase()}`;

    // Build indicators HTML
    const indicatorsHtml = analysis.indicators && analysis.indicators.length > 0
      ? `<ul class="dsa-indicators-list">
          ${analysis.indicators.map(ind => `<li class="dsa-indicator-item">${ind}</li>`).join('')}
         </ul>`
      : '<p style="font-size: 11px; color: #a3e635; margin-top: 4px; padding-left: 4px;">✓ Safe content environment</p>';

    // Build flaggedPhrases warning pills HTML
    const phrases = Array.isArray(analysis.flaggedPhrases) ? analysis.flaggedPhrases : [];
    const flaggedPhrasesHtml = phrases.length > 0
      ? `<div class="dsa-flagged-phrases">
          ${phrases.map((phrase, index) =>
            `<span class="dsa-warning-pill" style="animation-delay: ${index * 60}ms">${phrase}</span>`
          ).join('')}
         </div>`
      : '<span class="dsa-no-flags">✓ No malicious phrases detected</span>';

    // Build summaryDetails block (only shown for "Unsure" classification)
    const summaryHtml = analysis.summaryDetails
      ? `<div style="margin-top: 6px; padding: 8px; background: rgba(245,158,11,0.08); border: 1px solid rgba(245,158,11,0.2); border-radius: 8px;">
           <span style="font-size: 10px; font-weight: 700; color: #f59e0b; text-transform: uppercase; letter-spacing: 0.8px;">⚠ Summary</span>
           <p style="font-size: 11px; color: #cbd5e1; margin-top: 4px; line-height: 1.5;">${analysis.summaryDetails}</p>
         </div>`
      : '';

    // Sender domain display line (shown if backend returned a domain)
    const senderHtml = analysis.senderDomain
      ? `<div class="dsa-metric">
           <span>Sender Domain:</span>
           <span class="dsa-metric-val" style="font-family: monospace;">${analysis.senderDomain}</span>
         </div>`
      : '';

    const scannedAt = analysis.analyzedAt
      ? new Date(analysis.analyzedAt).toLocaleTimeString()
      : new Date().toLocaleTimeString();

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

      ${senderHtml}

      ${summaryHtml}

      <div style="margin-top: 6px;">
        <span style="font-size: 11px; font-weight: bold; color: #94a3b8;">Key Indicators:</span>
        ${indicatorsHtml}
      </div>

      <div style="font-size: 9px; color: #64748b; text-align: right; margin-top: 2px;">
        Scanned at: ${scannedAt}
      </div>

      <!-- Extended View Toggle Button -->
      <button class="dsa-toggle-btn" aria-expanded="false" aria-controls="dsa-extended-panel">
        <span>View Detailed Analysis</span>
        <i class="dsa-toggle-chevron">&#9660;</i>
      </button>

      <!-- Extended View Collapsible Panel -->
      <div class="dsa-extended-view" id="dsa-extended-panel" role="region">
        <div class="dsa-extended-content">
          <span class="dsa-extended-label">Flagged Phrases</span>
          ${flaggedPhrasesHtml}
        </div>
      </div>
    `;

    // ── Scoped Event Listeners (no host-page conflicts) ──────

    // Close button
    card.querySelector('.dsa-close-btn').addEventListener('click', (e) => {
      e.stopPropagation();
      card.remove();
    });

    // Extended View accordion toggle
    const toggleBtn     = card.querySelector('.dsa-toggle-btn');
    const extendedPanel = card.querySelector('.dsa-extended-view');

    toggleBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      e.preventDefault();

      const isExpanded = toggleBtn.classList.contains('dsa-expanded');

      if (isExpanded) {
        toggleBtn.classList.remove('dsa-expanded');
        extendedPanel.classList.remove('dsa-open');
        toggleBtn.setAttribute('aria-expanded', 'false');
        toggleBtn.querySelector('span').textContent = 'View Detailed Analysis';
      } else {
        toggleBtn.classList.add('dsa-expanded');
        extendedPanel.classList.add('dsa-open');
        toggleBtn.setAttribute('aria-expanded', 'true');
        toggleBtn.querySelector('span').textContent = 'Hide Detailed Analysis';
      }
    });

    container.appendChild(card);
  },

  /**
   * Renders error feedback if communication with the background worker fails.
   * @param {HTMLElement} container - The badge container to append the error card to
   * @param {string}      errorMsg  - The error message string to display
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
