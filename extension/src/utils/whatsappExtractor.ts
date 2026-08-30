export interface WhatsAppExtractPayload {
  text: string;
  sender: string;
  isUnknownSender: boolean;
  hasCallEvent: boolean;
  hasExtractableContent: boolean;
}

/**
 * Extracts chat details and incoming messages from the active WhatsApp Web DOM.
 * Specifically targets text scams, unknown senders, and missed call banners.
 */
export const extractWhatsAppDOM = (): WhatsAppExtractPayload => {
  let sender = 'Unknown Sender';
  let isUnknownSender = false;
  let hasCallEvent = false;
  let textContent = '';
  let hasExtractableContent = false;

  try {
    // 1. Active Chat & Sender Extraction
    const headerContainer = 
      document.querySelector('#main header') || 
      document.querySelector('div[data-testid="conversation-header"]');

    if (headerContainer) {
      const titleEl = 
        headerContainer.querySelector('span[dir="auto"]') || 
        headerContainer.querySelector('[title]');

      if (titleEl) {
        sender = titleEl.getAttribute('title') || titleEl.textContent || 'Unknown Sender';
      }
    }

    // Clean sender string from WhatsApp's bidirectional formatting characters
    const cleanSender = sender.replace(/[\u200E\u200F\u202A-\u202E]/g, '').trim();

    // 2. Unknown Number Detection
    // Using E.164 regex check
    const phoneRegex = /^\+?[0-9\s\-()]{7,20}$/;
    if (phoneRegex.test(cleanSender)) {
      isUnknownSender = true;
    }

    // 3. Incoming Text & Embedded Link Aggregation
    // Target only incoming message bubbles
    const incomingBubbles = Array.from(
      document.querySelectorAll('.message-in, div[data-id^="false_"]')
    );

    // Keep the latest 15 messages for context
    const recentBubbles = incomingBubbles.slice(-15);
    const extractedMessages: string[] = [];

    recentBubbles.forEach((bubble) => {
      // 4. Call/Vishing Event Extraction
      const rawBubbleText = (bubble.textContent || '').toLowerCase();
      if (
        rawBubbleText.includes('missed voice call') ||
        rawBubbleText.includes('missed video call') ||
        bubble.querySelector('span[data-testid*="missed"]') !== null
      ) {
        hasCallEvent = true;
      }

      // Extract text content from selectable/copyable elements safely avoiding duplication
      let messageText = '';
      const selectableNodes = Array.from(bubble.querySelectorAll('span.selectable-text'));
      if (selectableNodes.length > 0) {
        messageText = selectableNodes.map(el => el.textContent?.trim() || '').join(' ');
      } else {
        const copyableNodes = Array.from(bubble.querySelectorAll('.copyable-text'));
        messageText = copyableNodes.map(el => el.textContent?.trim() || '').join(' ');
      }

      // Query embedded hyperlinks within the bubble
      const links = Array.from(bubble.querySelectorAll('a[href]'));
      links.forEach((link) => {
        const href = link.getAttribute('href');
        if (href) {
          messageText += ` [Link: ${href}]`;
        }
      });

      const finalMsgText = messageText.trim();
      if (finalMsgText) {
        // Clean up excessive whitespace
        extractedMessages.push(finalMsgText.replace(/\s+/g, ' '));
      }
    });

    textContent = extractedMessages.join('\n');
    hasExtractableContent = textContent.length > 0 || hasCallEvent;

    return {
      text: textContent,
      sender: cleanSender || sender,
      isUnknownSender,
      hasCallEvent,
      hasExtractableContent
    };

  } catch (error) {
    console.error('DigiSafe: Error extracting WhatsApp DOM', error);
    return {
      text: '',
      sender: 'Unknown Sender',
      isUnknownSender: false,
      hasCallEvent: false,
      hasExtractableContent: false
    };
  }
};
