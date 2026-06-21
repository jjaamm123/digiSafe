import express from 'express';
import { GoogleGenAI } from '@google/genai';

const router = express.Router();

// Initialize the Google Gen AI client if API Key is available
const apiKey = process.env.GEMINI_API_KEY;
let ai = null;

if (apiKey && apiKey !== 'your_gemini_api_key_here') {
  try {
    ai = new GoogleGenAI({ apiKey });
    console.log('[Digital Safety Backend] Google Gen AI SDK initialized successfully with API Key.');
  } catch (error) {
    console.error('[Digital Safety Backend] Failed to initialize Google Gen AI client:', error);
  }
} else {
  console.log('[Digital Safety Backend] No GEMINI_API_KEY found. Running in OFFLINE Fallback Mock Mode.');
}

// System Prompt provided by the user
const SYSTEM_PROMPT = `You are an expert Cybersecurity Threat Intelligence API. 
Your sole function is to analyze digital communications (emails, messages, web text) and detect phishing, financial scams, social engineering, and malicious misinformation.

You must analyze the provided user text and return your assessment STRICTLY as a JSON object. Do not include markdown formatting, conversational text, or any other output besides the JSON.

Perform your analysis based on these criteria:
1. HIGH RISK (Score 80-100): Clear malicious intent, credential harvesting, aggressive urgency, suspicious links, or known scam typologies.
2. MEDIUM RISK (Score 40-79): Suspicious elements, unusual requests for information or money, unverified claims, but lacks definitive malicious payload.
3. LOW RISK (Score 0-39): Standard communication, safe marketing, or benign text.`;

// Gemini Response JSON Schema configuration for Structured Outputs
const RESPONSE_SCHEMA = {
  type: 'OBJECT',
  properties: {
    riskLevel: {
      type: 'STRING',
      enum: ['HIGH', 'MEDIUM', 'LOW']
    },
    riskScore: {
      type: 'INTEGER'
    },
    classification: {
      type: 'STRING',
      enum: ['Phishing Attempt', 'Financial Scam', 'Misinformation', 'Clean / Safe']
    },
    indicators: {
      type: 'ARRAY',
      items: { type: 'STRING' },
      description: 'Array of 1 to 3 short, specific sentences explaining why this score was given. Be highly specific to the text.'
    },
    flaggedPhrases: {
      type: 'ARRAY',
      items: { type: 'STRING' },
      description: 'Array of 1 to 5 exact words or short phrases pulled directly from the user text that triggered the risk score. If safe, leave empty.'
    }
  },
  required: ['riskLevel', 'riskScore', 'classification', 'indicators', 'flaggedPhrases']
};

/**
 * Local Fallback Threat Analyzer (for offline use and verification)
 */
const analyzeTextLocalFallback = (text = '') => {
  const lowercaseText = text.toLowerCase();
  
  if (lowercaseText.includes('password') || lowercaseText.includes('credential') || lowercaseText.includes('update your account')) {
    return {
      riskLevel: 'HIGH',
      riskScore: 88,
      classification: 'Phishing Attempt',
      indicators: ['Requests credential modifications', 'Urgent call-to-action phrasing detected'],
      flaggedPhrases: ['password', 'credential', 'update your account']
    };
  }
  
  if (lowercaseText.includes('transfer') || lowercaseText.includes('money') || lowercaseText.includes('urgent') || lowercaseText.includes('inheritance')) {
    return {
      riskLevel: 'MEDIUM',
      riskScore: 65,
      classification: 'Financial Scam',
      indicators: ['Suspicious monetary mentions', 'High-pressure urgency markers'],
      flaggedPhrases: ['transfer', 'money', 'urgent']
    };
  }

  if (lowercaseText.includes('fake news') || lowercaseText.includes('conspiracy') || lowercaseText.includes('unverified source')) {
    return {
      riskLevel: 'MEDIUM',
      riskScore: 50,
      classification: 'Misinformation',
      indicators: ['Mentions unverified claims', 'Sensationalist style indicators'],
      flaggedPhrases: ['fake news', 'unverified source']
    };
  }

  return {
    riskLevel: 'LOW',
    riskScore: 12,
    classification: 'Clean / Safe',
    indicators: ['No typical phishing, scam, or misinformation markers found'],
    flaggedPhrases: []
  };
};

// POST /api/scan
router.post('/scan', async (req, res, next) => {
  try {
    const { text, source } = req.body;

    if (!text || typeof text !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Bad Request',
        message: 'Invalid payload: "text" field is required and must be a string'
      });
    }

    console.log(`\n--- [${new Date().toISOString()}] Scan Request Received ---`);
    console.log(`Source: ${source || 'Unknown'}`);
    console.log(`Content Length: ${text.length} characters`);
    console.log(`Content Preview: "${text.substring(0, 150)}${text.length > 150 ? '...' : ''}"`);

    let analysisResult = null;
    let isMock = true;

    // Use Gemini API if initialized
    if (ai) {
      try {
        console.log('Routing request to Gemini AI Engine...');
        const response = await ai.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: text,
          config: {
            systemInstruction: SYSTEM_PROMPT,
            responseMimeType: 'application/json',
            responseSchema: RESPONSE_SCHEMA,
            // Low temperature ensures deterministic, objective risk evaluations
            temperature: 0.1
          }
        });

        if (response.text) {
          analysisResult = JSON.parse(response.text);
          isMock = false;
          console.log('Gemini Analysis Successful.');
        } else {
          throw new Error('Received empty response from Gemini API');
        }
      } catch (geminiError) {
        console.error('Gemini API call failed, falling back to local analysis:', geminiError);
      }
    }

    // Fallback if Gemini failed or is not configured
    if (!analysisResult) {
      console.log('Running Fallback Heuristics analysis...');
      analysisResult = analyzeTextLocalFallback(text);
      isMock = true;
    }

    // Standardize response payload
    const responsePayload = {
      success: true,
      data: {
        analyzedAt: new Date().toISOString(),
        source: source || 'unknown',
        isMock: isMock,
        riskLevel: analysisResult.riskLevel,
        riskScore: analysisResult.riskScore,
        classification: analysisResult.classification,
        indicators: analysisResult.indicators,
        flaggedPhrases: analysisResult.flaggedPhrases
      }
    };

    console.log(`Result: ${analysisResult.classification} (Risk: ${analysisResult.riskScore}%, Level: ${analysisResult.riskLevel}, Mock: ${isMock})`);
    console.log(`---------------------------------------------------------\n`);

    return res.json(responsePayload);
  } catch (error) {
    next(error);
  }
});

export default router;
