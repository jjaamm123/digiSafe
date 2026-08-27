export interface ScanRequest {
  text: string;
  source?: string;
  userId?: string;
}

export interface ScanResponse {
  classification: 'Phishing' | 'Scam' | 'Misinformation' | 'Safe';
  riskScore: number;
  indicators: string[];
  flaggedPhrases: string[];
  isMock?: boolean;
}
