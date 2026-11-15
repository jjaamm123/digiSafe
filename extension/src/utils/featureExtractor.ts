import { BlindThreatDigest } from '../types/threat';
export function buildBlindDigest(
  text: string,
  platform: 'gmail' | 'whatsapp' | 'linkedin',
  sender: string = '',
  riskScore: number = 0,
  threatCategory: 'Safe' | 'Suspicious' | 'Phishing' | 'Scam' = 'Safe',
  flaggedPhrases: string[] = [],
  linkForensics: Array<{ url: string; hostname: string; isSuspicious: boolean }> = []
): BlindThreatDigest {
  const safeSender = sender || '';
  const safeText = text || '';
  const safeLinks = linkForensics || [];
  const safePhrases = flaggedPhrases || [];

  const isKnownEnterprise = /@(google\.com|microsoft\.com|apple\.com|evernote\.com|linkedin\.com)$/i.test(safeSender);
  const hasDoc = safeLinks.some((l) => /docs\.google|dropbox|drive\.google/i.test(l.hostname));
  const badLinks = safeLinks.filter((l) => l.isSuspicious).length;

  return {
    platform,
    riskScore,
    threatCategory,
    metrics: {
      textLength: safeText.length,
      urlCount: safeLinks.length,
      suspiciousUrlCount: badLinks,
      flaggedPhraseCount: safePhrases.length,
    },
    signals: {
      isUnknownSender: !isKnownEnterprise && (/^[+\d]/.test(safeSender) || safeSender.toLowerCase().includes('unknown')),
      isVerifiedEnterpriseDomain: isKnownEnterprise,
      hasDocSharingLink: hasDoc,
      hasUrgencyCoercion: /immediately|urgent|within \d+|suspended/i.test(safeText),
      hasFinancialHooks: /wire|transfer|bank|crypto|salary|payment/i.test(safeText),
      hasCredentialHarvesting: /password|login|verify identity|account action/i.test(safeText),
    },
    topTargetDomain: safeLinks[0]?.hostname || undefined,
    primaryFlaggedTerm: safePhrases[0] || undefined,
  };
}
