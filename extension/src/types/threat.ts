/**
 * threat.ts — DigiSafe Structured Forensic Evidence Schema
 *
 * Defines strongly-typed forensic structures produced by the on-device
 * Explainable AI (XAI) engine and presented in the UI.
 */

export type ThreatCategory =
  | 'Legitimate Transactional'
  | 'Task / Job Recruitment Scam'
  | 'Credential Phishing'
  | 'Account Impersonation'
  | 'Urgent Coercion'
  | 'Safe Conversation'
  | 'Verified Safe';

export interface LinkForensicItem {
  url: string;
  hostname: string;
  isSuspicious: boolean;
  reason?: string;
}

export interface SenderIdentityForensics {
  raw: string;
  isVerifiedDomain: boolean;
  isUnsavedNumber: boolean;
  domainOrPhone: string;
  senderType?: 'official_domain' | 'unsaved_phone' | 'generic_display_name';
}

export interface ExtractedEvidence {
  category: ThreatCategory;
  riskScore: number; // 0 to 100
  senderIdentity: SenderIdentityForensics;
  quotedPhrases: string[]; // Exact offending strings extracted from the message
  flaggedPhrases?: string[];
  triggerKeywords?: string[];
  detectedLinks?: string[];
  linkForensics: LinkForensicItem[];
  specificAnalysis: string; // Dynamically synthesized forensic paragraph
  actionableGuidance: string; // Context-aware advice based on detected vector
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
