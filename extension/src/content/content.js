/**
 * Digital Safety AI Platform - Content Script
 * 
 * Scalable foundation for detecting target elements on Gmail and LinkedIn,
 * extracting their text content, and invoking the DOM injector.
 */

(function () {
  console.log('[Digital Safety AI] Content script initialized.');

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
          // Return the latest email content text in the thread view
          const latestBody = bodyContainers[bodyContainers.length - 1];
          return latestBody.innerText.trim();
        }
        return anchor.innerText.trim();
      },
      // Locate the element to append the "Scan" badge to
      getBadgeAnchor: (anchor) => anchor
    },
    linkedin: {
      domainMatch: 'linkedin.com',
      // Target individual post containers in the feed
      targetSelector: '.feed-shared-update-v2, .update-components-actor',
      getText: (post) => {
        // Find text block in the post
        const textElement = post.querySelector(
          '.feed-shared-update-v2__description, .feed-shared-text, .update-components-text, .feed-shared-update-v2__commentary'
        );
        return textElement ? textElement.innerText.trim() : post.innerText.trim();
      },
      getBadgeAnchor: (post) => {
        // Place badge near author metadata (name/timestamp header)
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
   * Processes a single matching element: extracts text and injects badge UI
   */
  function processElement(element) {
    // Avoid double processing
    if (element.dataset.dsaProcessed === 'true') return;
    element.dataset.dsaProcessed = 'true';

    try {
      const textToScan = activeConfig.getText(element);
      const badgeAnchor = activeConfig.getBadgeAnchor(element);

      if (!textToScan || textToScan.length < 5) {
        // Skip elements with negligible text content
        element.removeAttribute('data-dsa-processed'); // Allow reprocessing if text loads later
        return;
      }

      if (badgeAnchor && window.DigitalSafetyInjector) {
        console.log(`[Digital Safety AI] Target detected on ${activeKey}. Injecting scan badge.`);
        window.DigitalSafetyInjector.injectBadge(badgeAnchor, textToScan, activeKey);
      }
    } catch (err) {
      console.error('[Digital Safety AI] Error injecting badge for element:', err);
    }
  }

  // 1. Process elements present on initial load
  // Introduce a slight delay to allow client-side hydration (e.g. on LinkedIn/Gmail SPA transitions)
  setTimeout(processExistingTargets, 2000);

  // 2. Set up MutationObserver to detect dynamically loaded content
  const observer = new MutationObserver((mutations) => {
    let shouldScan = false;
    
    for (const mutation of mutations) {
      if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
        for (const node of mutation.addedNodes) {
          // Check if node is an element and matches or contains our selector
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
      // Debounce slightly to handle batch DOM additions efficiently
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
