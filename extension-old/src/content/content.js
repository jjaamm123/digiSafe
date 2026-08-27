/**
 * Digital Safety AI Platform - Content Script
 *
 * Scalable foundation for detecting target elements on Gmail and LinkedIn,
 * extracting their text content and sender metadata, and invoking the DOM injector.
 */

(function () {
  console.log('[Digital Safety AI] Content script initialized.');

  // ─────────────────────────────────────────────────────────────
  // Gmail Sender Extraction Helper
  // Attempts to pull the raw "from" email address out of the
  // Gmail message header card. Gmail renders sender info inside
  // a <span> with email="..." attribute, or inside a <span class="go">
  // element. We try multiple selectors in priority order.
  // ─────────────────────────────────────────────────────────────
  function extractGmailSender() {
    // Priority 1: The sender <span> inside the header that carries
    // an explicit `email` attribute (e.g. <span email="noreply@sbl.com.np">)
    const emailAttrEl = document.querySelector('[email]');
    if (emailAttrEl) {
      const raw = emailAttrEl.getAttribute('email').trim();
      if (raw && raw.includes('@')) return raw;
    }

    // Priority 2: The visible "from" address rendered in the .go span
    // (Gmail's internal class for the sender address chip)
    const goSpan = document.querySelector('.go');
    if (goSpan) {
      const raw = goSpan.innerText.trim();
      if (raw && raw.includes('@')) return raw;
    }

    // Priority 3: Any mailto: link inside the message header region
    const headerRegion = document.querySelector('.ha');
    if (headerRegion) {
      const mailtoLink = headerRegion.querySelector('a[href^="mailto:"]');
      if (mailtoLink) {
        const raw = mailtoLink.getAttribute('href').replace('mailto:', '').trim();
        if (raw && raw.includes('@')) return raw;
      }
    }

    // Priority 4: Scan all <span> elements for an email-like pattern
    // inside the message header wrapper (.hb is Gmail's header container)
    const headerWrapper = document.querySelector('.hb');
    if (headerWrapper) {
      const spans = headerWrapper.querySelectorAll('span');
      for (const span of spans) {
        const text = span.innerText.trim();
        if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(text)) return text;
      }
    }

    return ''; // Not found — backend will handle the missing field gracefully
  }

  // Site selectors & data extraction rules
  const SITE_CONFIGS = {
    gmail: {
      domainMatch: 'mail.google.com',
      // Target the subject line in an opened email thread
      targetSelector: 'h2.hP',
      // Extractor function to get relevant text to scan
      getText: (anchor) => {
        // Find email body containers in the active open thread
        const bodyContainers = document.querySelectorAll('.ii.gt, .a3s.aiL');
        if (bodyContainers && bodyContainers.length > 0) {
          const latestBody = bodyContainers[bodyContainers.length - 1];
          return latestBody.innerText.trim();
        }
        return anchor.innerText.trim();
      },
      // Extract raw sender email address from the Gmail header card
      getSender: () => extractGmailSender(),
      // Locate the element to append the "Scan" badge to
      getBadgeAnchor: (anchor) => anchor
    },
    linkedin: {
      domainMatch: 'linkedin.com',
      // Target individual post containers in the feed
      targetSelector: '.feed-shared-update-v2, .update-components-actor',
      getText: (post) => {
        const textElement = post.querySelector(
          '.feed-shared-update-v2__description, .feed-shared-text, .update-components-text, .feed-shared-update-v2__commentary'
        );
        return textElement ? textElement.innerText.trim() : post.innerText.trim();
      },
      // LinkedIn posts don't have an email sender — return empty string
      getSender: () => '',
      getBadgeAnchor: (post) => {
        return post.querySelector('.update-components-actor__meta, .feed-shared-actor__meta') || post;
      }
    }
  };

  // Identify active site config based on current hostname
  const hostname = window.location.hostname;
  let activeConfig = null;
  let activeKey = null;

  if (hostname.includes(SITE_CONFIGS.gmail.domainMatch)) {
    activeConfig = SITE_CONFIGS.gmail;
    activeKey = 'gmail';
  } else if (hostname.includes(SITE_CONFIGS.linkedin.domainMatch)) {
    activeConfig = SITE_CONFIGS.linkedin;
    activeKey = 'linkedin';
  }

  if (!activeConfig) {
    console.warn('[Digital Safety AI] Current domain is not supported by the active content script profile.');
    return;
  }

  console.log(`[Digital Safety AI] Active site profile loaded: ${activeKey.toUpperCase()}`);

  /**
   * Scans the document for target nodes and injects badges
   */
  function processExistingTargets() {
    try {
      const targets = document.querySelectorAll(activeConfig.targetSelector);
      targets.forEach(target => {
        processElement(target);
      });
    } catch (e) {
      console.error('[Digital Safety AI] Error processing target nodes:', e);
    }
  }

  /**
   * Processes a single matching element: extracts text + sender and injects badge UI
   */
  function processElement(element) {
    // Avoid double processing
    if (element.dataset.dsaProcessed === 'true') return;
    element.dataset.dsaProcessed = 'true';

    try {
      const textToScan = activeConfig.getText(element);
      const sender     = activeConfig.getSender(element); // Raw sender email (e.g. noreply@sbl.com.np)
      const badgeAnchor = activeConfig.getBadgeAnchor(element);

      if (!textToScan || textToScan.length < 5) {
        // Skip elements with negligible text content; allow reprocessing later
        element.removeAttribute('data-dsa-processed');
        return;
      }

      if (sender) {
        console.log(`[Digital Safety AI] Sender extracted: ${sender}`);
      } else {
        console.log('[Digital Safety AI] Sender not found in DOM — will proceed without sender metadata.');
      }

      if (badgeAnchor && window.DigitalSafetyInjector) {
        console.log(`[Digital Safety AI] Target detected on ${activeKey}. Injecting scan badge.`);
        // Pass sender as the fourth argument to the injector
        window.DigitalSafetyInjector.injectBadge(badgeAnchor, textToScan, activeKey, sender);
      }
    } catch (err) {
      console.error('[Digital Safety AI] Error injecting badge for element:', err);
    }
  }

  // 1. Process elements present on initial load
  setTimeout(processExistingTargets, 2000);

  // 2. Set up MutationObserver to detect dynamically loaded content
  const observer = new MutationObserver((mutations) => {
    let shouldScan = false;

    for (const mutation of mutations) {
      if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType === Node.ELEMENT_NODE) {
            if (node.matches(activeConfig.targetSelector)) {
              processElement(node);
            } else if (node.querySelector && node.querySelector(activeConfig.targetSelector)) {
              shouldScan = true;
            }
          }
        }
      }
    }

    if (shouldScan) {
      clearTimeout(window.dsaDebounceTimer);
      window.dsaDebounceTimer = setTimeout(processExistingTargets, 500);
    }
  });

  // Start observing DOM changes on the page body
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });

  console.log('[Digital Safety AI] MutationObserver active.');
})();
