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

function LinkedInScanner() {
  const [data, setData] = useState<ThreatData | null>(null);
  const [loading, setLoading] = useState(false);
  const [show, setShow] = useState(false);
  const [scannedPosts, setScannedPosts] = useState<Set<string>>(new Set());

  useEffect(() => {
    let debounceTimer: NodeJS.Timeout;

    const observer = new MutationObserver((mutations) => {
      // Look for LinkedIn posts
      const posts = document.querySelectorAll('.feed-shared-update-v2__description-wrapper, .update-components-text');
      
      let textToScan = '';
      
      posts.forEach(post => {
        const text = post.textContent?.trim();
        // Basic check to see if we haven't scanned this post text recently
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
    
    browser.runtime.sendMessage({
      type: 'SCAN_REQUEST',
      payload: { text, source: 'linkedin' }
    }).then((response: any) => {
      setLoading(false);
      if (response && response.success) {
        // Don't show modal for safe posts to avoid spamming the user on LinkedIn
        if (response.data.classification !== 'Safe') {
          setData(response.data);
        } else {
          setShow(false);
        }
      } else {
        setShow(false);
        console.error('Scan failed:', response?.error);
      }
    });
  };

  if (!show) return null;

  return (
    <ThreatReportModal 
      data={data} 
      loading={loading} 
      onClose={() => setShow(false)} 
    />
  );
}
