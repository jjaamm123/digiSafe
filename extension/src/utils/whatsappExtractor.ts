export interface WhatsAppChatContext {
  text: string;
  sender: string;
  isUnknownSender: boolean;
  hasLinks: boolean;
  detectedUrls: string[];
  hasMediaOrQr: boolean;
}

export function extractWhatsAppContext(): WhatsAppChatContext {
  try {
    const messageNodes = Array.from(document.querySelectorAll('div[data-pre-plain-text]')).slice(-15);
    
    if (messageNodes.length === 0) {
      return { text: '', sender: 'Unknown', isUnknownSender: false, hasLinks: false, detectedUrls: [], hasMediaOrQr: false };
    }

    let extractedText = '';
    let hasLinks = false;
    const detectedUrls: string[] = [];
    const urlRegex = /(https?:\/\/[^\s]+)/gi;

    messageNodes.forEach(node => {
      const metadata = node.getAttribute('data-pre-plain-text') || '';
      const messageText = (node as HTMLElement).innerText || '';
      extractedText += `${metadata} ${messageText}\n`;

      const matches = messageText.match(urlRegex);
      if (matches) {
        detectedUrls.push(...matches);
      }

      if (node.querySelector('a[href]')) {
        hasLinks = true;
      }
    });

    const headerElement = document.querySelector('header span[dir="auto"], header div[role="button"] span');
    const sender = headerElement ? (headerElement as HTMLElement).innerText : 'Unknown WhatsApp Chat';
    const isUnknownSender = /^\+?[0-9\s-]+$/.test(sender);

    return {
      text: extractedText.trim(),
      sender,
      isUnknownSender,
      hasLinks,
      detectedUrls,
      hasMediaOrQr: !!document.querySelector('div[data-pre-plain-text] img, div[data-pre-plain-text] canvas')
    };
  } catch (error) {
    return { text: '', sender: 'Error', isUnknownSender: false, hasLinks: false, detectedUrls: [], hasMediaOrQr: false };
  }
}
