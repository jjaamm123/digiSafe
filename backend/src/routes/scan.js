import express from 'express';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';
import { createClient } from '@supabase/supabase-js';

// Ensure environment variables are loaded
dotenv.config();

const router = express.Router();

// ─────────────────────────────────────────────────────────────
// 1. Client Initialization
// ─────────────────────────────────────────────────────────────
const apiKey = process.env.GEMINI_API_KEY;
let ai = null;

if (apiKey) {
  try {
    ai = new GoogleGenAI({ apiKey });
    console.log('[Digital Safety Backend] Google Gen AI SDK initialized successfully.');
  } catch (error) {
    console.error('[Digital Safety Backend] Failed to initialize Google Gen AI client:', error);
  }
} else {
  console.warn('[Digital Safety Backend] WARNING: No GEMINI_API_KEY found. Running in Fallback Mode.');
}

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
let supabase = null;

if (supabaseUrl && supabaseKey) {
  try {
    supabase = createClient(supabaseUrl, supabaseKey);
    console.log('[Digital Safety Backend] Supabase client initialized successfully.');
  } catch (error) {
    console.error('[Digital Safety Backend] Failed to initialize Supabase client:', error);
  }
} else {
  console.warn('[Digital Safety Backend] WARNING: Missing Supabase credentials.');
}

// ─────────────────────────────────────────────────────────────
// 2. Gemini System Prompt (built dynamically per-request)
// Injects current timestamp for temporal awareness and contains
// the Sender Verification + Unsure Failsafe guardrail logic.
// ─────────────────────────────────────────────────────────────
const buildSystemPrompt = (sender = '') => {
  // Inject live timestamp so the AI never hallucinates past/future dates
  const currentDateTime = new Date().toISOString();

  // Build the sender metadata block. When the Chrome extension successfully extracts
  // the raw "from" address from the Gmail header card, it is passed here explicitly
  // so the model does NOT have to guess or hunt for it inside the email body text.
  const senderBlock = sender
    ? `[SENDER VERIFICATION METADATA]:
- Claimed Sender Field: ${sender}
- Extracted Domain    : ${sender.includes('@') ? sender.split('@')[1].trim() : 'unknown'}

CRITICAL DOMAIN-MATCH OVERRIDE RULE:
If the domain extracted from the [SENDER VERIFICATION METADATA] above accurately matches
the real-world operational domain of the institution named inside the email body text
(for example: "@sbl.com.np" mapping to "Siddhartha Bank Limited", or "@nabilbank.com"
mapping to "Nabil Bank"), you MUST apply the following overrides:
  1. Classify the email as "Safe" — not "Unsure" and not "Phishing".
  2. Set riskScore to 15 or lower.
  3. Do NOT penalise the email for minor typos, formatting inconsistencies, or small
     numerical discrepancies in the email body — these are common in automated
     transactional messages and are NOT indicators of phishing on their own.
  4. Populate senderDomain with the extracted domain string.
  5. Leave flaggedPhrases as an empty array.
  6. Leave summaryDetails as an empty string.

This override exists because the sender address is authoritative metadata controlled by
the mail server, not by an attacker who can only influence the body text.
`
    : `[SENDER VERIFICATION METADATA]:
- Claimed Sender Field: NOT PROVIDED
- Extracted Domain    : unknown

No sender address was supplied by the scanner. You must attempt to extract it from
the email body text itself (headers, footers, reply-to fields, signature blocks).
If no domain can be identified, note this in indicators and apply conservative scoring.
`;

  return `You are an expert Cybersecurity Threat Intelligence API with temporal awareness.

CURRENT DATE AND TIME (ISO 8601): ${currentDateTime}
Use this timestamp as your ground truth when evaluating date-related claims in the text.
Do NOT hallucinate past or future dates. If the text references a date or time, compare
it against this timestamp before drawing conclusions.

${senderBlock}
────────────────────────────────────────────────
STEP 1 — SENDER DOMAIN ANALYSIS (MANDATORY)
────────────────────────────────────────────────
If the [SENDER VERIFICATION METADATA] block above contains a valid domain, use it as
your primary trust signal — do not override it with guesswork from the body text.

If you must fall back to scanning the body text for a domain:
- Extract the full sender domain (e.g., "alerts@siddharthabank.com" → "siddharthabank.com").
- Compare against the organization claimed in the body.
- Same root domain + official TLD = STRONG trust signal.
- Do NOT penalise for minor typos in transactional data tables (amounts, dates).
- Domain mismatch IS a strong phishing signal.

────────────────────────────────────────────────
STEP 2 — CLASSIFICATION WITH FAILSAFE LOGIC
────────────────────────────────────────────────
Classify the message into exactly ONE of these three states:

"Phishing" (riskScore 70–100):
  ONLY when you have concrete, verifiable evidence of malicious intent.
  Required evidence: mismatched sender domain, credential harvesting links,
  impersonation with domain mismatch, or known scam patterns with clear payload.
  Do NOT use if the sender domain legitimately matches the claimed organisation.

"Unsure" (riskScore 40–69):
  Your DEFAULT for all gray-area cases. When in doubt, always use "Unsure".
  Triggers: transactional email you cannot fully verify, legitimate-looking domain
  with minor anomalies, sensitive action requested from plausible domain.
  REQUIRED: populate summaryDetails with one neutral factual sentence.

"Safe" (riskScore 0–39):
  ONLY for clearly benign messages — newsletters, personal correspondence,
  or verified-domain transactional emails with no anomalies.

────────────────────────────────────────────────
STEP 3 — OUTPUT REQUIREMENTS
────────────────────────────────────────────────
- Return ONLY a valid JSON object. No markdown, no prose, no code fences.
- Be highly specific in indicators — reference actual phrases, domains, and dates.
- Only populate flaggedPhrases with GENUINE risk indicators.
- For "Safe" or "Phishing" classifications, summaryDetails must be an empty string "".`;
};

// ─────────────────────────────────────────────────────────────
// 3. Response JSON Schema
// Updated to include "Unsure" classification and summaryDetails
// ─────────────────────────────────────────────────────────────
const RESPONSE_SCHEMA = {
  type: 'OBJECT',
  properties: {
    riskLevel: {
      type: 'STRING',
      enum: ['HIGH', 'MEDIUM', 'LOW'],
      description: 'HIGH for Phishing, MEDIUM for Unsure, LOW for Safe.'
    },
    riskScore: {
      type: 'INTEGER',
      description: 'Risk score: 70-100 for Phishing, 40-69 for Unsure, 0-39 for Safe.'
    },
    classification: {
      type: 'STRING',
      enum: ['Phishing', 'Unsure', 'Safe'],
      description: 'Three-state classification. Default to Unsure for all gray-area emails.'
    },
    senderDomain: {
      type: 'STRING',
      description: 'The extracted sender email domain (e.g. "siddharthabank.com"). Empty string if not found.'
    },
    indicators: {
      type: 'ARRAY',
      items: { type: 'STRING' },
      description: 'Array of 1–4 specific, evidence-based sentences explaining the score. Reference actual text content, domains, and dates.'
    },
    flaggedPhrases: {
      type: 'ARRAY',
      items: { type: 'STRING' },
      description: 'Exact substrings from the text that are genuine risk indicators. Empty array if Safe or no real signals found.'
    },
    summaryDetails: {
      type: 'STRING',
      description: 'REQUIRED when classification is Unsure. A neutral, factual one-sentence summary of what the email is asking the user to do (e.g. "This message claims to be a transaction alert from Siddhartha Bank for NPR 1.50. The sender domain matches the bank, but proceed with caution."). Must be an empty string "" for Safe or Phishing classifications.'
    }
  },
  required: ['riskLevel', 'riskScore', 'classification', 'senderDomain', 'indicators', 'flaggedPhrases', 'summaryDetails']
};

// ─────────────────────────────────────────────────────────────
// 4. Fallback Heuristics (used when Gemini is unavailable)
// ─────────────────────────────────────────────────────────────
const getFallbackHeuristics = () => {
  return {
    isMock: true,
    riskLevel: 'LOW',
    riskScore: 0,
    classification: 'Safe',
    senderDomain: '',
    indicators: [
      'Fallback heuristics activated — AI analysis engine is unavailable or API key is missing.',
      'This result is not a real threat assessment. Configure GEMINI_API_KEY to enable live scanning.'
    ],
    flaggedPhrases: [],
    summaryDetails: ''
  };
};

// ─────────────────────────────────────────────────────────────
// POST /api/scan
// ─────────────────────────────────────────────────────────────
router.post('/scan', async (req, res) => {
  try {
    // Destructure sender — the raw email address extracted from the Gmail DOM header
    // by the Chrome extension (e.g. "noreply@sbl.com.np"). Falls back to empty string
    // when not provided (LinkedIn posts, missing header, older extension versions).
    const { text, source, sender = '' } = req.body;

    // Basic payload validation
    if (!text || typeof text !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Bad Request',
        message: 'Invalid payload: "text" field is required and must be a string.'
      });
    }

    const requestTimestamp = new Date().toISOString();
    console.log(`\n─── [${requestTimestamp}] Scan Request Received ───`);
    console.log(`Source       : ${source || 'Unknown'}`);
    console.log(`Sender       : ${sender  || '(not provided)'}`);
    console.log(`Content Len  : ${text.length} characters`);
    console.log(`Preview      : "${text.substring(0, 120)}${text.length > 120 ? '...' : ''}"`);

    let analysisResult = null;
    let isMock = true;

    // ── Gemini AI Analysis ──────────────────────────────────
    if (ai) {
      try {
        // Build the system prompt fresh per request:
        // injects the current timestamp AND the sender address as an authoritative
        // metadata block so the model can apply the domain-match override rule.
        const systemPrompt = buildSystemPrompt(sender);

        console.log(`Routing to Gemini 2.5 Flash [sender=${sender || 'none'}]...`);

        const response = await ai.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: text,
          config: {
            systemInstruction: systemPrompt,
            responseMimeType: 'application/json', // Enforce strict JSON output
            responseSchema: RESPONSE_SCHEMA,
            temperature: 0.1 // Near-zero temp for deterministic, objective threat scoring
          }
        });

        if (response.text) {
          analysisResult = JSON.parse(response.text);
          isMock = false;
          console.log(`Gemini Result : ${analysisResult.classification} (Score: ${analysisResult.riskScore}, Domain: "${analysisResult.senderDomain || 'not found'}")`);
        } else {
          throw new Error('Received an empty response body from the Gemini API.');
        }
      } catch (aiError) {
        // Log but never crash — fall through to heuristics
        console.error('Gemini API call failed. Falling back to mock heuristics:', aiError.message || aiError);
      }
    }

    // ── Fallback if Gemini unavailable or errored ───────────
    if (!analysisResult) {
      console.log('Applying Fallback Heuristics (isMock = true)...');
      analysisResult = getFallbackHeuristics();
      isMock = true;
    }

    // ── Telemetry → Supabase (only for live AI results) ─────
    if (!isMock && supabase) {
      try {
        const eventId = crypto.randomUUID();
        const userId = '0c182d52-887f-482e-8b87-12339c971fd5'; // Placeholder — replaced by real auth in Phase 3

        const scanEventRecord = {
          id: eventId,
          user_id: userId,
          source: source || 'unknown',
          threat_category: analysisResult.classification,
          confidence_score: analysisResult.riskScore,
          ai_explanation: analysisResult.indicators.join(' ')
        };

        const { error: dbError } = await supabase
          .from('scan_events')
          .insert([scanEventRecord]);

        if (dbError) {
          console.error('Supabase Insertion Error:', dbError);
        } else {
          console.log(`Telemetry recorded → Supabase (Event ID: ${eventId})`);
        }
      } catch (telemetryError) {
        // Telemetry failure must never block the response to the user
        console.error('Telemetry pipeline error (non-fatal):', telemetryError.message || telemetryError);
      }
    }

    // ── Final Response ───────────────────────────────────────
    return res.json({
      success: true,
      data: {
        analyzedAt: requestTimestamp,
        source: source || 'unknown',
        isMock,
        riskLevel:       analysisResult.riskLevel,
        riskScore:       analysisResult.riskScore,
        classification:  analysisResult.classification,
        senderDomain:    analysisResult.senderDomain   ?? '',
        indicators:      analysisResult.indicators     ?? [],
        flaggedPhrases:  analysisResult.flaggedPhrases ?? [],
        summaryDetails:  analysisResult.summaryDetails ?? ''
      }
    });

  } catch (error) {
    // Ultimate catch-all — server must never crash
    console.error('Unhandled Server Error in POST /api/scan:', error.message || error);

    const fallback = getFallbackHeuristics();
    return res.json({
      success: true,
      data: {
        analyzedAt: new Date().toISOString(),
        source: req.body?.source || 'unknown',
        ...fallback
      }
    });
  }
});

export default router;
