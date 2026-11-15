import { defineContentScript } from 'wxt/sandbox';
import { createShadowRootUi } from 'wxt/client';
import { createRoot } from 'react-dom/client';
import React, { useState, useEffect } from 'react';
import { ThreatReportModal, ThreatData } from '@/components/ThreatReportModal';
import tailwindCss from '@/assets/tailwind.css?inline';

export default defineContentScript({
  matches: ['https://www.linkedin.com/*'],
  
  async main(ctx) {
    const ui = await createShadowRootUi(ctx, {
      name: 'digisafe-linkedin-overlay',
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
        root.render(<LinkedInScanner />);
        return root;
      },
      onRemove: (root) => {
        root?.unmount();
      },
    });

    ui.mount();
  },
});

function extractLinkedInAuthor(textContext: string = ''): string {
  const txtLower = textContext.toLowerCase();
  if (
    txtLower.includes('linkedin security') || 
    txtLower.includes('security notice') || 
    document.querySelector('.notification-badge') || 
    document.querySelector('[data-test-app-aware-link]')?.textContent?.includes('LinkedIn')
  ) {
    return 'LinkedIn System <security-noreply@linkedin.com>';
  }

  const authorEl =
    document.querySelector('.feed-shared-actor__name span') ||
    document.querySelector('.update-components-actor__name span') ||
    document.querySelector('.msg-s-message-group__name');
    
  return authorEl?.textContent?.trim() || 'Unknown LinkedIn User';
}

function LinkedInScanner() {
  const [data, setData] = useState<ThreatData | null>(null);
  const [loading, setLoading] = useState(false);
  const [show, setShow] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scannedPosts, setScannedPosts] = useState<Set<string>>(new Set());

  useEffect(() => {
    let debounceTimer: NodeJS.Timeout;

    const observer = new MutationObserver((mutations) => {
      const posts = document.querySelectorAll('.feed-shared-update-v2__description-wrapper, .update-components-text');
      
      let textToScan = '';
      
      posts.forEach(post => {
        const text = post.textContent?.trim();
        if (text && text.length > 30 && !scannedPosts.has(text.substring(0, 50))) {
          textToScan = text;
          setScannedPosts(prev => new Set(prev).add(text.substring(0, 50)));
        }
      });

      if (textToScan) {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
          scanPost(textToScan);
        }, 2000);
      }
    });

    observer.observe(document.body, { childList: true, subtree: true });

    return () => {
      observer.disconnect();
      clearTimeout(debounceTimer);
    };
  }, [scannedPosts]);

  const scanPost = async (text: string) => {
    if (loading) return;
    
    setLoading(true);
    setShow(true);
    setError(null);

    if (!chrome.runtime?.id) {
      setLoading(false);
      setError('Extension updated. Please refresh the tab to reconnect.');
      return;
    }
    
    browser.runtime.sendMessage({
      type: 'SCAN_REQUEST',
      payload: { text, sender: extractLinkedInAuthor(text), source: 'linkedin' }
    }).then((response: any) => {
      setLoading(false);
      if (response && response.success) {
        if (response.data.classification !== 'Safe') {
          setData(response.data);
        } else {
          setShow(false);
        }
      } else {
        const errMsg = response?.error || 'Scan failed. Please refresh and try again.';
        console.error('Scan failed:', errMsg);
        setError(errMsg);
      }
    }).catch((err: any) => {
      setLoading(false);
      const errMsg = err?.message || 'Connection error. Please refresh and try again.';
      console.error('Message error:', errMsg);
      setError(errMsg);
    });
  };

  if (!show) return null;

  return (
    <ThreatReportModal 
      data={data} 
      loading={loading}
      error={error}
      onClose={() => {
        setShow(false);
        setError(null);
      }} 
    />
  );
}
