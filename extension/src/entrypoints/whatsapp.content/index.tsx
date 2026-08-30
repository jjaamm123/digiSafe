import { defineContentScript } from 'wxt/sandbox';
import { createShadowRootUi } from 'wxt/client';
import { createRoot } from 'react-dom/client';
import React, { useState, useEffect } from 'react';
import { ThreatReportModal, ThreatData } from '@/components/ThreatReportModal';
import tailwindCss from '@/assets/tailwind.css?inline';
import { extractWhatsAppDOM, WhatsAppExtractPayload } from '@/utils/whatsappExtractor';

export default defineContentScript({
  matches: ['https://web.whatsapp.com/*'],
  
  async main(ctx) {
    const ui = await createShadowRootUi(ctx, {
      name: 'digisafe-whatsapp-overlay',
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
        root.render(<WhatsAppScanner />);
        return root;
      },
      onRemove: (root) => {
        root?.unmount();
      },
    });

    ui.mount();
  },
});

function WhatsAppScanner() {
  const [data, setData] = useState<ThreatData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [payload, setPayload] = useState<WhatsAppExtractPayload | null>(null);

  useEffect(() => {
    let debounceTimer: NodeJS.Timeout;

    const checkChat = () => {
      // Basic check if a chat is open
      const headerContainer = document.querySelector('#main header') || document.querySelector('div[data-testid="conversation-header"]');
      if (headerContainer) {
        const chatData = extractWhatsAppDOM();
        setPayload(chatData);
      } else {
        setPayload(null);
      }
    };

    const observer = new MutationObserver(() => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        checkChat();
      }, 1000); // Debounce a bit longer for WhatsApp since it changes a lot
    });

    observer.observe(document.body, { childList: true, subtree: true });
    checkChat(); // initial check

    return () => {
      observer.disconnect();
      clearTimeout(debounceTimer);
    };
  }, []);

  const handleScan = async () => {
    if (!payload || loading) return;
    
    // Virtualized DOM Resilience
    if (!payload.hasExtractableContent) {
      setError('No text or links found in recent incoming messages to scan.');
      return;
    }

    setLoading(true);
    setError(null);
    
    try {
      // Session Invalidation Guard
      if (!chrome.runtime?.id) {
        throw new Error('Extension context invalidated. Please refresh the page.');
      }

      const response: any = await chrome.runtime.sendMessage({
        type: 'SCAN_REQUEST',
        payload: { 
          text: payload.text, 
          source: 'whatsapp',
          sender: payload.sender,
          isUnknownSender: payload.isUnknownSender,
          hasCallEvent: payload.hasCallEvent
        }
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

  // Only render scanner button/overlay if a chat is active
  if (!payload) return null;

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
