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

function GmailScanner() {
  const [data, setData] = useState<ThreatData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [emailText, setEmailText] = useState<string | null>(null);

  useEffect(() => {
    let lastUrl = window.location.hash;
    let debounceTimer: NodeJS.Timeout;

    const checkEmail = () => {
      const emailBody = document.querySelector('.a3s.aiL');
      if (emailBody && emailBody.textContent && emailBody.textContent.trim().length > 20) {
        setEmailText(emailBody.textContent);
      } else {
        setEmailText(null);
      }
    };

    const observer = new MutationObserver(() => {
      // Handle SPA navigation by clearing data on URL hash change
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
      clearTimeout(debounceTimer);
    };
  }, []);

  const handleScan = async () => {
    if (!emailText || loading) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const response: any = await browser.runtime.sendMessage({
        type: 'SCAN_REQUEST',
        payload: { text: emailText, source: 'gmail' }
      });
      
      setLoading(false);
      if (response && response.success) {
        try {
          const payloadData = response.data?.data || response.data || response;
          
          const scanData: ThreatData = {
            classification: payloadData.classification || payloadData.threatCategory || 'Safe',
            riskScore: payloadData.riskScore ?? payloadData.risk_score ?? 0,
            indicators: payloadData.indicators || [],
            flaggedPhrases: payloadData.flaggedPhrases || payloadData.flagged_phrases || [],
            isMock: payloadData.isMock || false
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

  // Do not render anything if no email text is detected on screen
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
