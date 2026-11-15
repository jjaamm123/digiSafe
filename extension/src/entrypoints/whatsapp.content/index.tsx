import { defineContentScript } from 'wxt/sandbox';
import { createShadowRootUi } from 'wxt/client';
import { createRoot } from 'react-dom/client';
import React, { useState, useEffect, useCallback, useRef } from 'react';
import { ThreatReportModal, ThreatData } from '@/components/ThreatReportModal';
import tailwindCss from '@/assets/tailwind.css?inline';
import { extractWhatsAppContext } from '@/utils/whatsappExtractor';

let resetScannerCallback: (() => void) | null = null;

export default defineContentScript({
  matches: ['https://web.whatsapp.com/*'],

  async main(ctx) {
    let ui: any = null;
    let isCreatingUi = false;
    let reactRoot: any = null;
    let lastChatTitle: string | null = null;

    const getWhatsAppHeader = (): Element | null => {
      const mainHeader = document.querySelector('#main header');
      if (mainHeader) return mainHeader;
      const header = document.querySelector('header');
      if (header && !header.closest('#side')) return header;
      return null;
    };

    const getChatTitle = (header: Element): string | null => {
      const titleEl = header.querySelector('span[dir="auto"], [title]');
      return titleEl?.getAttribute('title') || titleEl?.textContent?.trim() || null;
    };

    const mountOrReinject = async () => {
      const header = getWhatsAppHeader();
      if (!header) return;

      const existingContainer = header.querySelector('digisafe-whatsapp-overlay');
      if (existingContainer) return;

      if (!ui) {
        if (isCreatingUi) return;
        isCreatingUi = true;
        try {
          ui = await createShadowRootUi(ctx, {
            name: 'digisafe-whatsapp-overlay',
            position: 'inline',
            anchor: () => getWhatsAppHeader(),
            append: 'last',
            onMount: (container) => {
              let appContainer = container.querySelector('#digisafe-whatsapp-root') as HTMLElement | null;
              if (!appContainer || !reactRoot) {
                container.innerHTML = '';
                const style = document.createElement('style');
                style.textContent = tailwindCss;
                container.appendChild(style);

                appContainer = document.createElement('div');
                appContainer.id = 'digisafe-whatsapp-root';
                appContainer.style.display = 'flex';
                appContainer.style.alignItems = 'center';
                appContainer.style.marginLeft = '12px';
                container.appendChild(appContainer);

                reactRoot = createRoot(appContainer);
              }
              reactRoot.render(<WhatsAppScanner />);
              return reactRoot;
            },
            onRemove: () => {
            },
          });
        } catch (err) {
          console.error('[DigiSafe WhatsApp] Failed to initialize UI:', err);
          ui = null;
          return;
        } finally {
          isCreatingUi = false;
        }
      }

      if (ui) {
        try {
          ui.mount();
        } catch (err) {
          console.warn('[DigiSafe WhatsApp] Remount error:', err);
        }
      }
    };

    const observer = new MutationObserver(() => {
      const header = getWhatsAppHeader();
      if (!header) return;

      const currentTitle = getChatTitle(header);
      if (currentTitle && currentTitle !== lastChatTitle) {
        lastChatTitle = currentTitle;
        if (resetScannerCallback) {
          resetScannerCallback();
        }
      }

      const existingContainer = header.querySelector('digisafe-whatsapp-overlay');
      if (!existingContainer) {
        mountOrReinject();
      }
    });

    observer.observe(document.body, { childList: true, subtree: true });

    ctx.onInvalidated(() => {
      observer.disconnect();
    });

    mountOrReinject();
  },
});

function WhatsAppScanner() {
  const [data, setData] = useState<ThreatData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const lastChatTitleRef = useRef<string | null>(null);

  const resetState = useCallback(() => {
    setData(null);
    setLoading(false);
    setError(null);
  }, []);

  useEffect(() => {
    resetScannerCallback = resetState;
    return () => {
      if (resetScannerCallback === resetState) {
        resetScannerCallback = null;
      }
    };
  }, [resetState]);

  useEffect(() => {
    const getTitle = () => {
      const header = document.querySelector('#main header, header');
      const titleEl = header?.querySelector('span[dir="auto"], [title]');
      return titleEl?.getAttribute('title') || titleEl?.textContent || null;
    };

    lastChatTitleRef.current = getTitle();

    const titleObserver = new MutationObserver(() => {
      const newTitle = getTitle();
      if (newTitle && newTitle !== lastChatTitleRef.current) {
        lastChatTitleRef.current = newTitle;
        resetState();
      }
    });

    const targetNode = document.querySelector('#main') || document.body;
    titleObserver.observe(targetNode, {
      childList: true,
      subtree: true,
      characterData: true,
    });

    return () => {
      titleObserver.disconnect();
    };
  }, [resetState]);

  const handleScan = async () => {
    if (loading) return;

    const chatData = extractWhatsAppContext();

    if (!chatData.text && !chatData.hasMediaOrQr) {
      setError('No recent incoming messages or media detected to scan.');
      return;
    }

    setLoading(true);
    setError(null);
    setData(null);

    try {
      if (!chrome.runtime?.id) {
        throw new Error('Extension context invalidated. Please refresh the page.');
      }

      const response: any = await chrome.runtime.sendMessage({
        type: 'SCAN_REQUEST',
        payload: {
          text: chatData.text || '[Media/QR Code payload in chat]',
          source: 'whatsapp',
          sender: chatData.sender,
          metadata: {
            isUnknownSender: chatData.isUnknownSender,
            hasLinks: chatData.hasLinks,
            urls: chatData.detectedUrls,
            hasMediaOrQr: chatData.hasMediaOrQr,
          },
        },
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
      positionClass="relative"
      modalPositionClass="fixed top-24 right-8"
    />
  );
}
