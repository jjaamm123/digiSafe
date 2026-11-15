import { defineContentScript } from 'wxt/sandbox';
import { createShadowRootUi } from 'wxt/client';
import { createRoot } from 'react-dom/client';
import React, { useState, useEffect } from 'react';
import { ThreatReportModal, ThreatData } from '@/components/ThreatReportModal';
import tailwindCss from '@/assets/tailwind.css?inline';

export default defineContentScript({
  matches: ['https://mail.google.com/*'],
  
  async main(ctx) {
    const ui = await createShadowRootUi(ctx, {
      name: 'digisafe-gmail-overlay',
      position: 'inline',
      anchor: 'body',
      append: 'last',
      onMount: (container) => {
        const style = document.createElement('style');
        style.textContent = tailwindCss;
        container.appendChild(style);

        const appContainer = document.createElement('div');
        container.appendChild(appContainer);

        const root = createRoot(appContainer);
        root.render(<GmailScanner />);
        return root;
      },
      onRemove: (root) => {
        root?.unmount();
      },
    });

    ui.mount();
  },
});

function purgeLegacyElements() {
  try {
    const legacySelectors = [
      '.dsa-badge-container',
      '.dsa-result-card',
      '.dsa-scan-button',
      '.dsa-error-text',
    ];
    document.querySelectorAll(legacySelectors.join(',')).forEach((el) => el.remove());

    document.querySelectorAll('button, div, span').forEach((el) => {
      const txt = el.textContent || '';
      if (
        txt.includes('Scan Security') ||
        txt.includes('Ensure the backend server is running on http://localhost:5000') ||
        (el.classList?.contains('dsa-title') && txt.includes('Scan Failed'))
      ) {
        const container = el.closest('.dsa-badge-container') || el.closest('.dsa-result-card') || el;
        container.remove();
      }
    });
  } catch {
    // Defensive pass
  }
}

function GmailScanner() {
  const [data, setData] = useState<ThreatData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [emailText, setEmailText] = useState<string | null>(null);

  useEffect(() => {
    let lastUrl = window.location.hash;
    let debounceTimer: NodeJS.Timeout;

    purgeLegacyElements();
    const purgeInterval = setInterval(purgeLegacyElements, 400);

    const checkEmail = () => {
      purgeLegacyElements();
      const emailBody = document.querySelector('.a3s.aiL');
      if (emailBody && emailBody.textContent && emailBody.textContent.trim().length > 20) {
        setEmailText(emailBody.textContent);
      } else {
        setEmailText(null);
      }
    };

    const observer = new MutationObserver(() => {
      purgeLegacyElements();

      if (window.location.hash !== lastUrl) {
        lastUrl = window.location.hash;
        setData(null);
        setError(null);
        setLoading(false);
      }

      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        checkEmail();
      }, 500);
    });

    observer.observe(document.body, { childList: true, subtree: true });
    checkEmail(); // initial check

    return () => {
      observer.disconnect();
      clearInterval(purgeInterval);
      clearTimeout(debounceTimer);
    };
  }, []);

  const handleScan = async () => {
    if (!emailText || loading) return;
    
    setLoading(true);
    setError(null);
    
    try {
      let senderEmail = 'Unknown Sender';
      const senderEl = document.querySelector('.gD');
      if (senderEl) {
        const name = senderEl.getAttribute('name');
        const email = senderEl.getAttribute('email');
        if (name && email) {
          senderEmail = `${name} <${email}>`;
        } else if (email) {
          senderEmail = email;
        } else if (name) {
          senderEmail = name;
        } else {
          senderEmail = senderEl.textContent || 'Unknown Sender';
        }
      } else {
        const fallbackEl = document.querySelector('span[email], div.go span');
        if (fallbackEl) {
          senderEmail = fallbackEl.getAttribute('email') || fallbackEl.textContent || 'Unknown Sender';
        }
      }

      if (!chrome.runtime?.id) {
        throw new Error('Extension updated. Please refresh the tab to reconnect.');
      }

      const response: any = await browser.runtime.sendMessage({
        type: 'SCAN_REQUEST',
        payload: { text: emailText, sender: senderEmail, source: 'gmail' }
      });
      
      setLoading(false);
      if (response && response.success) {
        try {
          const payloadData = response.data?.data || response.data || response;
          
          const scanData: ThreatData = {
            classification: payloadData.classification || payloadData.threatCategory || 'Safe',
            category: payloadData.category,
            riskScore: payloadData.riskScore ?? payloadData.risk_score ?? 0,
            sender: payloadData.sender,
            senderIdentity: payloadData.senderIdentity,
            indicators: payloadData.indicators || [],
            flaggedPhrases: payloadData.flaggedPhrases || payloadData.flagged_phrases || [],
            quotedPhrases: payloadData.quotedPhrases || [],
            triggerKeywords: payloadData.triggerKeywords || [],
            detectedLinks: payloadData.detectedLinks || [],
            linkForensics: payloadData.linkForensics || [],
            explanation: payloadData.explanation || '',
            actionableGuidance: payloadData.actionableGuidance || '',
            evidence: payloadData.evidence,
            isMock: payloadData.isMock || false,
            isLocalTriage: payloadData.isLocalTriage || false,
            engine: payloadData.engine,
          };

          setData(scanData);
        } catch (parseErr: any) {
          console.error('Data parsing/rendering error:', parseErr);
          setError('Failed to parse scan results.');
        }
      } else {
        console.error('Scan failed:', response?.error);
        setError(response?.error || 'Network error occurred during scan.');
      }
    } catch (err: any) {
      setLoading(false);
      console.error('Message failed:', err);
      setError(err.message || 'Connection error.');
    }
  };

  if (!emailText) return null;

  return (
    <ThreatReportModal 
      data={data} 
      loading={loading} 
      error={error}
      onScan={handleScan}
      onClose={() => {
        setData(null);
        setError(null);
      }} 
    />
  );
}
