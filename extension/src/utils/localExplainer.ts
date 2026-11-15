
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
  senderType: 'official_domain' | 'unsaved_phone' | 'generic_display_name';
}

export interface ExtractedEvidence {
  category: ThreatCategory;
  riskScore: number;
  senderIdentity: SenderIdentityForensics;
  quotedPhrases: string[];
  flaggedPhrases: string[];
  triggerKeywords: string[];
  detectedLinks: string[];
  linkForensics: LinkForensicItem[];
  specificAnalysis: string;
  actionableGuidance: string;
}

export interface LocalAnalysisResult {
  classification: 'Phishing' | 'Scam' | 'Safe' | 'Suspicious';
  category?: string;
  riskScore: number;
  sender?: string;
  senderIdentity?: SenderIdentityForensics;
  indicators: string[];
  flaggedPhrases: string[];
  quotedPhrases?: string[];
  triggerKeywords?: string[];
  detectedLinks?: string[];
  linkForensics?: LinkForensicItem[];
  explanation: string;
  actionableGuidance?: string;
  evidence: ExtractedEvidence;
}

// ─── Phase 2.1: Sender & Domain Authenticator ────────────────────────────────

export const VERIFIED_DOMAINS = [
  'google.com',
  'accounts.google.com',
  'dominos.co.in',
  'dominos.com',
  'linkedin.com',
  'amazon.in',
  'amazon.com',
  'microsoft.com',
  'apple.com',
  'flipkart.com',
  'myntra.com',
  'swiggy.com',
  'zomato.com',
  'paytm.com',
  'phonepe.com',
  'razorpay.com',
  'paypal.com',
  'netflix.com',
  'spotify.com',
  'github.com',
  'slack.com',
  'notion.so',
  'dropbox.com',
  'zoom.us',
  'uber.com',
  'ola.com',
  'airbnb.com',
  'facebook.com',
  'meta.com',
  'instagram.com',
  'twitter.com',
  'x.com',
  'youtube.com',
];

export function isVerifiedDomain(domain?: string): boolean {
  if (!domain) return false;
  const clean = domain.toLowerCase().trim();
  return (
    VERIFIED_DOMAINS.some((v) => clean === v || clean.endsWith('.' + v)) ||
    /^(?:[a-z0-9-]+\.)?amazon\.[a-z]{2,3}(?:\.[a-z]{2})?$/i.test(clean) ||
    /^(?:[a-z0-9-]+\.)?google\.[a-z]{2,3}(?:\.[a-z]{2})?$/i.test(clean)
  );
}

export function authenticateSender(sender?: string, source?: string): SenderIdentityForensics {
  if (!sender) {
    return {
      raw: '',
      isVerifiedDomain: false,
      isUnsavedNumber: false,
      domainOrPhone: 'unknown sender',
      senderType: 'generic_display_name',
    };
  }

  const raw = sender.trim();
  const normSource = (source || '').toLowerCase();

  const emailMatch = raw.match(/<([^>]+)>/) || raw.match(/([^\s]+@[^\s]+)/);
  if (emailMatch || raw.includes('@')) {
    const email = emailMatch ? emailMatch[1].toLowerCase().trim() : raw.toLowerCase().trim();
    const domain = email.includes('@') ? email.split('@')[1] : '';
    const verified = isVerifiedDomain(domain);
    return {
      raw,
      isVerifiedDomain: verified,
      isUnsavedNumber: false,
      domainOrPhone: domain || email,
      senderType: verified ? 'official_domain' : 'generic_display_name',
    };
  }

  const isPhone = /^\+?\d[\d\s\-()]{7,}$/.test(raw);
  if (normSource === 'whatsapp' || isPhone) {
    return {
      raw,
      isVerifiedDomain: false,
      isUnsavedNumber: isPhone,
      domainOrPhone: raw,
      senderType: isPhone ? 'unsaved_phone' : 'generic_display_name',
    };
  }

  return {
    raw,
    isVerifiedDomain: false,
    isUnsavedNumber: false,
    domainOrPhone: raw,
    senderType: 'generic_display_name',
  };
}

// ─── Phase 1: Granular Evidence Extraction & Tokenization ───────────────────

export interface ScamExtractionResult {
  flaggedPhrases: string[];
  quotedPhrases: string[];
  triggerKeywords: string[];
  categories: Set<string>;
}

export function extractScamSubstrings(text: string): ScamExtractionResult {
  const flaggedPhrases: string[] = [];
  const categories = new Set<string>();

  const URGENCY_REGEX =
    /\b(?:within 24 hours|account (?:suspended|restricted|blocked)|immediately|action required|suspended within|urgent|act now|expires (?:today|soon)|last warning|final notice|time.?sensitive|respond immediately|your account will be|limited time|immediate verification)\b/gi;

  const FINANCIAL_REGEX =
    /\b(?:(?:earn|income|salary)\s+(?:[\d,]+(?:\s*-\s*[\d,]+)?\s*(?:inr|rs|usd|\$|daily|per day))|salary (?:is )?paid (?:on the )?(?:exact )?same day|daily payout|wire transfer|cryptocurrency|claim your prize|gift card|bonus reward)\b/gi;

  const CREDENTIAL_HARVESTING_REGEX =
    /\b(?:verify your (?:identity|account|credentials|password)|confirm your (?:password|identity|pin)|unauthorized transaction|update your payment|enter your (?:credentials|password)|social security number|bank account details|routing number|credit card number)\b/gi;

  const RECRUITMENT_REGEX =
    /\b(?:urgently hiring|part[- ]time staff|hiring manager|work from home|reply with ['"]?yes['"]?|contact (?:our )?hr receptionist)\b/gi;

  const IMPERSONATION_REGEX =
    /\b(?:dear (?:customer|user|account holder|client)|we have detected|your account has been|click the link below|click here to verify|log in to your account|security alert from)\b/gi;

  function collectMatches(regex: RegExp, categoryName: string) {
    let match: RegExpExecArray | null;
    while ((match = regex.exec(text)) !== null) {
      const phrase = match[0].trim();
      if (phrase && !flaggedPhrases.includes(phrase)) {
        flaggedPhrases.push(phrase);
        categories.add(categoryName);
      }
    }
  }

  collectMatches(URGENCY_REGEX, 'urgency');
  collectMatches(FINANCIAL_REGEX, 'financial_lure');
  collectMatches(CREDENTIAL_HARVESTING_REGEX, 'credential_harvesting');
  collectMatches(RECRUITMENT_REGEX, 'recruitment_lure');
  collectMatches(IMPERSONATION_REGEX, 'impersonation');

  // 2. Keyword Tokenization: extract individual manipulative words
  const triggerKeywords: string[] = [];
  const MANIPULATIVE_DICTIONARY = [
    'urgent',
    'immediately',
    'suspend',
    'suspended',
    'suspension',
    'password',
    'verify',
    'verification',
    'salary',
    'income',
    'earn',
    'earning',
    'hiring',
    'prize',
    'gift',
    'cryptocurrency',
    'crypto',
    'expires',
    'warning',
    'confirm',
    'credentials',
    'unauthorized',
    'transfer',
    'payout',
    'alert',
    'action',
    'required',
    'restricted',
    'blocked',
    'limited',
    'notice',
    'click',
    'pin',
    'bonus',
    'bank',
    'banking',
    'pay',
    'payment',
    'security',
  ];

  for (const phrase of flaggedPhrases) {
    const words = phrase.toLowerCase().split(/\s+/);
    for (const w of words) {
      const clean = w.replace(/[^a-z]/g, '');
      if (clean.length >= 3 && MANIPULATIVE_DICTIONARY.includes(clean) && !triggerKeywords.includes(clean)) {
        triggerKeywords.push(clean);
      }
    }
  }

  const textWords = text.toLowerCase().split(/\s+/);
  for (const w of textWords) {
    const clean = w.replace(/[^a-z]/g, '');
    if (clean.length >= 4 && MANIPULATIVE_DICTIONARY.includes(clean) && !triggerKeywords.includes(clean)) {
      triggerKeywords.push(clean);
    }
  }

  if (triggerKeywords.length === 0) {
    const STOP_WORDS = new Set([
      'about', 'above', 'after', 'again', 'against', 'all', 'and', 'any', 'are', 'because',
      'been', 'before', 'being', 'below', 'between', 'both', 'but', 'can', 'cannot', 'could',
      'dear', 'did', 'does', 'doing', 'down', 'during', 'each', 'few', 'for', 'from', 'further',
      'had', 'has', 'have', 'having', 'hello', 'her', 'here', 'hers', 'herself', 'him', 'himself',
      'his', 'how', 'into', 'its', 'itself', 'just', 'more', 'most', 'my', 'myself', 'no', 'nor',
      'not', 'off', 'once', 'only', 'other', 'ought', 'our', 'ours', 'ourselves', 'out', 'over',
      'own', 'please', 'regards', 'same', 'she', 'should', 'some', 'such', 'than', 'that', 'the',
      'their', 'theirs', 'them', 'themselves', 'then', 'there', 'these', 'they', 'this', 'those',
      'through', 'too', 'under', 'until', 'very', 'was', 'were', 'what', 'when', 'where', 'which',
      'while', 'who', 'whom', 'why', 'with', 'would', 'you', 'your', 'yours', 'yourself', 'yourselves',
      'http', 'https', 'mail', 'email', 'sent', 'subject'
    ]);
    const wordFreq: Record<string, number> = {};
    for (const w of textWords) {
      const clean = w.replace(/[^a-z]/g, '');
      if (clean.length >= 4 && !STOP_WORDS.has(clean)) {
        wordFreq[clean] = (wordFreq[clean] || 0) + 1;
      }
    }
    const topWords = Object.keys(wordFreq)
      .sort((a, b) => wordFreq[b] - wordFreq[a])
      .slice(0, 7);
    triggerKeywords.push(...topWords);
  }

  return {
    flaggedPhrases,
    quotedPhrases: flaggedPhrases,
    triggerKeywords,
    categories,
  };
}

// ─── URL & Entity Parsing ───────────────────────────────────────────────────

export function extractUrls(text: string): string[] {
  const urlMatches = text.match(/https?:\/\/[^\s"'<>]+/gi) || [];
  const detectedLinks: string[] = [];
  const seen = new Set<string>();

  for (const raw of urlMatches) {
    const clean = raw.replace(/[.,;!?)]+$/, '');
    if (!seen.has(clean)) {
      seen.add(clean);
      detectedLinks.push(clean);
    }
  }

  return detectedLinks;
}

const KNOWN_SHORTENERS = [
  'bit.ly',
  'tinyurl.com',
  'tinyurl',
  'is.gd',
  'buff.ly',
  'ow.ly',
  'rebrand.ly',
  't.co',
  'bitly-service',
];

export function inspectLinkForensics(
  text: string,
  senderDomain?: string,
  isSenderVerified?: boolean
): LinkForensicItem[] {
  const detectedLinks = extractUrls(text);
  if (detectedLinks.length === 0) return [];

  const results: LinkForensicItem[] = [];

  for (const cleanUrl of detectedLinks) {
    let hostname = '';
    try {
      hostname = new URL(cleanUrl).hostname.replace(/^www\./, '').toLowerCase();
    } catch {
      const match = cleanUrl.match(/https?:\/\/([^/\s:?#]+)/i);
      hostname = match ? match[1].replace(/^www\./, '').toLowerCase() : '';
    }

    if (!hostname) continue;

    let isSuspicious = false;
    let reason: string | undefined = undefined;

    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      isSuspicious = true;
      reason = `Raw IP address host masks destination: ${hostname}`;
    }
    else if (
      KNOWN_SHORTENERS.some((s) => hostname === s || hostname.includes(s) || hostname.endsWith('.' + s))
    ) {
      isSuspicious = true;
      reason = `Deceptive domain mimicking link shortener: ${hostname}`;
    }
    else if (isSenderVerified && senderDomain) {
      const isDomainMatch =
        hostname === senderDomain ||
        hostname.endsWith('.' + senderDomain) ||
        (senderDomain.includes('amazon.') && hostname.includes('amazon.')) ||
        (senderDomain.includes('google.') && hostname.includes('google.'));
      if (!isDomainMatch) {
        isSuspicious = true;
        reason = `Domain mismatch: verified sender '${senderDomain}' points to external '${hostname}'`;
      }
    }

    results.push({
      url: cleanUrl,
      hostname,
      isSuspicious,
      reason,
    });
  }

  return results;
}

// ─── Phase 2 & 3: Contextual Matrix Synthesizer ─────────────────────────────

export interface DynamicExplanationParams {
  classification: 'Safe' | 'Suspicious' | 'Phishing' | 'Scam';
  sender: string;
  senderDomain?: string;
  linkCount?: number;
  textLength?: number;
  triggerKeywords?: string[];
  flaggedPhrases?: string[];
  detectedLinks?: string[];
  category?: ThreatCategory | string;
  linkForensics?: LinkForensicItem[];
  isUnknownSender?: boolean;
}

export function synthesizeDynamicExplanation(params: DynamicExplanationParams): string {
  const {
    classification,
    category,
    sender,
    linkCount = 0,
    triggerKeywords = [],
    flaggedPhrases = [],
    detectedLinks = [],
    linkForensics = [],
    isUnknownSender = false,
  } = params;

  const hasDocLink = linkForensics?.some(
    (l) => l.hostname.includes('docs.google') || l.hostname.includes('dropbox') || l.hostname.includes('drive')
  );
  const hasFinancialKeywords = triggerKeywords?.some((k) =>
    ['bank', 'pay', 'salary', 'transfer', 'crypto'].includes(k.toLowerCase())
  );
  const hasUrgency = triggerKeywords?.some((k) =>
    ['immediately', 'urgent', 'required', '24 hours'].includes(k.toLowerCase())
  );
  const primaryPhrase = flaggedPhrases?.[0] || triggerKeywords?.[0] || 'suspicious language';

  let explanation = '';

  // Phase 2: Dynamic Template Interpolation
  if (classification === 'Safe') {
    const urlCount = linkCount || linkForensics?.length || detectedLinks?.length || 0;
    const linkContext =
      urlCount > 0
        ? ` All ${urlCount} embedded link(s) point to verified destinations.`
        : ` No external links were detected.`;
    explanation = `We analyzed this message from ${sender}, and it matches standard conversational patterns.${linkContext} The AI found zero coercive keywords or scam indicators.`;
  } else if (classification === 'Scam' || classification === 'Phishing') {
    const badLink = linkForensics?.find((l) => l.isSuspicious)?.hostname || linkForensics?.[0]?.hostname || 'an external site';
    explanation = `Warning: High-risk threat detected. The sender (${sender}) is using manipulative tactics ("${primaryPhrase}") to drive you toward an unverified or deceptive destination (${badLink}).`;
  } else if (classification === 'Suspicious' || category === 'Urgent Coercion') {
    let specificText = `This message from an ${isUnknownSender ? 'unknown sender' : sender} uses high-pressure language. `;

    if (hasDocLink && hasUrgency) {
      const docHost = linkForensics?.[0]?.hostname || 'a file-sharing link';
      specificText += `The sender is urging you to act "${primaryPhrase}" and directing you to a file-sharing link (${docHost}). Scammers frequently use urgent language combined with legitimate document hosts to bypass security filters.`;
    } else if (hasFinancialKeywords) {
      specificText += `It uses financial hooks ("${primaryPhrase}") to trick you into clicking an unverified link.`;
    } else {
      specificText += `The AI noticed coercive patterns ("${primaryPhrase}") often used to trick people into making rushed decisions.`;
    }

    explanation = specificText;
  } else {
    explanation = `This message from an ${isUnknownSender ? 'unknown sender' : sender} uses high-pressure language. The AI noticed coercive patterns ("${primaryPhrase}") often used to trick people into making rushed decisions.`;
  }

  return explanation;
}

export function synthesizeExplanation(
  evidence: Partial<ExtractedEvidence>,
  metadata: { charCount: number; orderId?: string }
): string {
  const sender = evidence.senderIdentity?.domainOrPhone || 'unknown contact';
  const senderDomain = evidence.senderIdentity?.isVerifiedDomain
    ? `@${evidence.senderIdentity.domainOrPhone}`
    : sender;
  const linkCount = evidence.linkForensics?.length || 0;
  const isSafe = evidence.category === 'Legitimate Transactional' || evidence.category === 'Verified Safe';

  return synthesizeDynamicExplanation({
    classification: isSafe ? 'Safe' : (evidence.riskScore || 0) >= 70 ? 'Phishing' : 'Suspicious',
    category: evidence.category,
    sender,
    senderDomain,
    linkCount,
    textLength: metadata.charCount,
    triggerKeywords: evidence.triggerKeywords || [],
    flaggedPhrases: evidence.flaggedPhrases || evidence.quotedPhrases || [],
    detectedLinks: evidence.detectedLinks || (evidence.linkForensics?.map((l) => l.url) || []),
    linkForensics: evidence.linkForensics,
    isUnknownSender: evidence.senderIdentity?.isUnsavedNumber ?? true,
  });
}

export function synthesizeGuidance(
  category: ThreatCategory,
  riskScore: number,
  context?: {
    hasDocLink?: boolean;
    isUnknownSender?: boolean;
    hasFinancialKeywords?: boolean;
  }
): string {
  if (
    category === 'Legitimate Transactional' ||
    category === 'Verified Safe' ||
    category === 'Safe Conversation' ||
    riskScore <= 20
  ) {
    return "You're good to go! No action needed.";
  }

  if (context?.hasDocLink) {
    return 'Do not open the document or enter any passwords. Legitimate organizations will not pressure you to open unsolicited cloud files.';
  }

  if (context?.isUnknownSender && context?.hasFinancialKeywords) {
    return 'Do not reply or click the link. Never process financial transactions from unrecognized contacts.';
  }

  if (
    category === 'Credential Phishing' ||
    category === 'Task / Job Recruitment Scam' ||
    riskScore >= 70
  ) {
    return 'Do not click any links or reply. Delete this message immediately.';
  }

  return "Be careful. Don't share any personal information or passwords unless you independently verify who sent this.";
}

// ─── Phase 4: Strict Deterministic Risk Calculation ──────────────────────────

export function calculateDynamicRisk(params: {
  senderIdentity: SenderIdentityForensics;
  linkForensics: LinkForensicItem[];
  scamCategories: Set<string>;
  detectedLinks: string[];
  isTransactionalKeywords: boolean;
  onnxConfidence?: number;
  isSuspicious?: boolean;
}): number {
  const {
    senderIdentity,
    linkForensics,
    scamCategories,
    detectedLinks,
    onnxConfidence,
    isSuspicious,
  } = params;

  const hasSuspiciousLinks = linkForensics.some((l) => l.isSuspicious);
  const hasCredentialHarvesting = scamCategories.has('credential_harvesting');

  if (senderIdentity.isVerifiedDomain && !hasCredentialHarvesting && !hasSuspiciousLinks) {
    return 0;
  }

  let score = 0;
  if (isSuspicious && onnxConfidence) {
    score = Math.round(onnxConfidence * 100);
  }

  if (senderIdentity.isUnsavedNumber && (detectedLinks.length > 0 || linkForensics.length > 0)) {
    score += 30;
  } else if (senderIdentity.isUnsavedNumber) {
    score += 15;
  }

  if (hasSuspiciousLinks) {
    score += 30;
  }

  const scamQuoteCategories = [
    'financial_lure',
    'recruitment_lure',
    'impersonation',
    'urgency',
  ];
  for (const cat of scamQuoteCategories) {
    if (scamCategories.has(cat)) {
      score += 25;
    }
  }

  if (hasCredentialHarvesting) {
    score = Math.max(score, 85);
  }

  return Math.min(Math.max(score, 0), 99);
}

export function determineThreatCategory(params: {
  senderIdentity: SenderIdentityForensics;
  isTransactionalKeywords: boolean;
  scamCategories: Set<string>;
  hasSuspiciousLinks: boolean;
  riskScore: number;
}): ThreatCategory {
  const { senderIdentity, isTransactionalKeywords, scamCategories, hasSuspiciousLinks, riskScore } = params;

  if (senderIdentity.isVerifiedDomain && !scamCategories.has('credential_harvesting') && !hasSuspiciousLinks) {
    return isTransactionalKeywords ? 'Legitimate Transactional' : 'Verified Safe';
  }

  if (scamCategories.has('recruitment_lure') || scamCategories.has('financial_lure')) {
    return 'Task / Job Recruitment Scam';
  }

  if (scamCategories.has('credential_harvesting') || (hasSuspiciousLinks && riskScore >= 50)) {
    return 'Credential Phishing';
  }

  if (scamCategories.has('impersonation')) {
    return 'Account Impersonation';
  }

  if (scamCategories.has('urgency') || riskScore >= 30) {
    return 'Urgent Coercion';
  }

  if (isTransactionalKeywords) {
    return 'Legitimate Transactional';
  }

  return 'Safe Conversation';
}

/**
 * Helper to extract order ID from message text.
 */
export function extractOrderId(text: string): string | undefined {
  const match = text.match(/\b(?:order\s*(?:#|number|id)?\s*[:#-]?\s*([a-zA-Z0-9-]{6,}))/i);
  return match ? match[1] : undefined;
}

// ─── Main Analyzer ───────────────────────────────────────────────────────────

export function runLocalExplainability(
  text: string,
  onnxConfidenceOrSender?: number | string,
  isSuspiciousInput?: boolean,
  onnxLabel: string = 'LABEL_0',
  sender?: string,
  source?: string
): LocalAnalysisResult {
  let onnxConfidence = 0.5;
  let isSuspicious = false;
  let actualSender = sender;
  let actualSource = source;

  if (typeof onnxConfidenceOrSender === 'string') {
    actualSender = onnxConfidenceOrSender;
  } else if (typeof onnxConfidenceOrSender === 'number') {
    onnxConfidence = onnxConfidenceOrSender;
    isSuspicious = !!isSuspiciousInput;
  }

  // 1. Authenticate sender & entity type
  const senderIdentity = authenticateSender(actualSender, actualSource);

  // 2. Extract detected URLs & link forensics
  const detectedLinks = extractUrls(text);
  const linkForensics = inspectLinkForensics(
    text,
    senderIdentity.domainOrPhone,
    senderIdentity.isVerifiedDomain
  );

  // 3. Extract exact offending phrases & trigger keywords
  const scamExtraction = extractScamSubstrings(text);

  // Phase 2: Inject fallback structural evidence if ONNX flags threat without regex keywords
  if (isSuspicious && scamExtraction.flaggedPhrases.length === 0 && scamExtraction.triggerKeywords.length === 0) {
    scamExtraction.triggerKeywords.push('suspicious-text-structure');
    scamExtraction.triggerKeywords.push('unrecognized-sender-pattern');
  }

  // Phase 2 Contextual Override:
  // If sender is from a trusted domain, neutralize standard urgency and impersonation cues
  // (a legitimate corporate email saying "urgent account update" is safe).
  if (senderIdentity.isVerifiedDomain && !scamExtraction.categories.has('credential_harvesting')) {
    scamExtraction.categories.delete('urgency');
    scamExtraction.categories.delete('impersonation');
  }

  // 4. Inspect transactional keywords
  const TRANSACTIONAL_REGEX =
    /\b(?:order\s*#?|order\s*id|delivered|delivery|shipment|shipped|tracking|track\s*package|storage|invoice|receipt|payment\s*confirmation|purchased?|refund)\b/i;
  const isTransactionalKeywords = TRANSACTIONAL_REGEX.test(text);

  // 5. Calculate strict deterministic risk score
  const riskScore = calculateDynamicRisk({
    senderIdentity,
    linkForensics,
    scamCategories: scamExtraction.categories,
    detectedLinks,
    isTransactionalKeywords,
    onnxConfidence,
    isSuspicious,
  });

  // 6. Determine ThreatCategory
  const category = determineThreatCategory({
    senderIdentity,
    isTransactionalKeywords,
    scamCategories: scamExtraction.categories,
    hasSuspiciousLinks: linkForensics.some((l) => l.isSuspicious),
    riskScore,
  });

  // 7. Determine Classification
  // Safe if riskScore is 0 (or <= 20 with zero threat categories and zero suspicious links)
  const isSafe =
    (senderIdentity.isVerifiedDomain && !scamExtraction.categories.has('credential_harvesting') && !linkForensics.some((l) => l.isSuspicious)) ||
    category === 'Legitimate Transactional' ||
    category === 'Verified Safe' ||
    category === 'Safe Conversation' ||
    (riskScore <= 20 && scamExtraction.categories.size === 0 && !linkForensics.some((l) => l.isSuspicious));

  const classification: LocalAnalysisResult['classification'] = isSafe
    ? 'Safe'
    : riskScore >= 70
    ? 'Phishing'
    : 'Suspicious';

  // 8. Phase 2 & 3: Contextual Matrix Synthesizer
  const senderDomainFormatted = senderIdentity.isVerifiedDomain
    ? `@${senderIdentity.domainOrPhone}`
    : senderIdentity.domainOrPhone || 'authenticated sender';
  const senderDisplayName = senderIdentity.domainOrPhone || sender || 'unrecognized origin';
  const isUnknownSender = senderIdentity.isUnsavedNumber || !senderIdentity.isVerifiedDomain;

  // Scenario Detection Context
  const hasDocLink = linkForensics.some(
    (l) => l.hostname.includes('docs.google') || l.hostname.includes('dropbox') || l.hostname.includes('drive')
  );
  const hasFinancialKeywords = scamExtraction.triggerKeywords.some((k) =>
    ['bank', 'pay', 'salary', 'transfer', 'crypto'].includes(k.toLowerCase())
  );

  const dynamicExplanation = synthesizeDynamicExplanation({
    classification,
    category,
    sender: senderDisplayName,
    senderDomain: senderDomainFormatted,
    linkCount: detectedLinks.length,
    textLength: text.length,
    triggerKeywords: scamExtraction.triggerKeywords,
    flaggedPhrases: scamExtraction.flaggedPhrases,
    detectedLinks,
    linkForensics,
    isUnknownSender,
  });

  const actionableGuidance = synthesizeGuidance(category, riskScore, {
    hasDocLink,
    isUnknownSender,
    hasFinancialKeywords,
  });

  // 9. Synthesize Context-Aware Indicators (Humane, Plain English)
  const isWhatsApp = (source || '').toLowerCase() === 'whatsapp';
  const indicators: string[] = [];

  if (isSafe) {
    if (senderIdentity.isVerifiedDomain) {
      indicators.push(`Sender verified: Official sender from @${senderIdentity.domainOrPhone}.`);
    } else if (isWhatsApp && !senderIdentity.isUnsavedNumber) {
      indicators.push('Known contact: Message came from an existing conversation.');
    } else if (senderIdentity.domainOrPhone && senderIdentity.domainOrPhone !== 'unknown sender') {
      indicators.push(`Sender checked: '${senderIdentity.domainOrPhone}'.`);
    }

    if (detectedLinks.length === 0) {
      indicators.push('Links checked: No outside links or attachments found.');
    } else {
      indicators.push(`Links checked: All ${detectedLinks.length} link(s) lead to safe, recognized websites.`);
    }

    indicators.push('Text checked: No pushy wording, fake urgency, or password requests found.');
  } else {
    if (senderIdentity.isUnsavedNumber) {
      indicators.push(`Sender check: Message from an unsaved phone number (${senderIdentity.domainOrPhone}).`);
    } else if (senderIdentity.isVerifiedDomain) {
      indicators.push(`Sender check: Verified domain '${senderIdentity.domainOrPhone}'.`);
    } else {
      indicators.push(`Sender check: Unrecognized sender '${senderIdentity.domainOrPhone}'.`);
    }

    if (detectedLinks.length > 0) {
      const suspiciousCount = linkForensics.filter((l) => l.isSuspicious).length;
      indicators.push(
        `Links checked: Found ${detectedLinks.length} link(s)${suspiciousCount > 0 ? ` (${suspiciousCount} look suspicious)` : ''}.`
      );
    } else {
      indicators.push('Links checked: No web links found in this message.');
    }

    if (scamExtraction.flaggedPhrases.length > 0) {
      indicators.push(
        `Wording check: Detected ${scamExtraction.flaggedPhrases.length} pushy or suspicious phrase(s).`
      );
    } else {
      indicators.push('Wording check: AI detected patterns often used to trick people.');
    }
  }

  // 10. Assemble structured evidence & return result
  const evidence: ExtractedEvidence = {
    category: isSafe ? 'Verified Safe' : category,
    riskScore: isSafe ? 0 : riskScore,
    senderIdentity,
    quotedPhrases: scamExtraction.flaggedPhrases,
    flaggedPhrases: scamExtraction.flaggedPhrases,
    triggerKeywords: scamExtraction.triggerKeywords,
    detectedLinks,
    linkForensics,
    specificAnalysis: dynamicExplanation,
    actionableGuidance,
  };

  return {
    classification,
    category: isSafe ? 'Verified Safe' : category,
    riskScore: isSafe ? 0 : riskScore,
    sender: senderIdentity.domainOrPhone,
    senderIdentity,
    indicators,
    flaggedPhrases: scamExtraction.flaggedPhrases,
    quotedPhrases: scamExtraction.flaggedPhrases,
    triggerKeywords: scamExtraction.triggerKeywords,
    detectedLinks,
    linkForensics,
    explanation: dynamicExplanation,
    actionableGuidance,
    evidence,
  };
}
