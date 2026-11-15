export interface TelemetryPayload {
  source: string;
  threat_category: string;
  confidence_score: number;
  raw_text_length: number;
  indicators: string[];
}

export interface TelemetryResponse {
  success: boolean;
  logged: boolean;
}

export interface BlindThreatDigest {
  platform: 'gmail' | 'whatsapp' | 'linkedin';
  riskScore: number;                 // 0 to 100
  threatCategory: 'Safe' | 'Suspicious' | 'Phishing' | 'Scam';
  metrics: {
    textLength: number;
    urlCount: number;
    suspiciousUrlCount: number;
    flaggedPhraseCount: number;
  };
  signals: {
    isUnknownSender: boolean;
    isVerifiedEnterpriseDomain: boolean;
    hasDocSharingLink: boolean;      // e.g. Google Docs, Dropbox
    hasUrgencyCoercion: boolean;
    hasFinancialHooks: boolean;
    hasCredentialHarvesting: boolean;
  };
  topTargetDomain?: string;          // e.g. "docs.google.com" or "unverified-external" (No raw URLs)
  primaryFlaggedTerm?: string;       // e.g. "immediately" or "verify account"
}
