import express from 'express';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';
import { createClient } from '@supabase/supabase-js';

// Ensure environment variables are loaded
dotenv.config();

const router = express.Router();

// 1. Dependencies & Initialization
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
  console.warn('[Digital Safety Backend] WARNING: No GEMINI_API_KEY found.');
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

// 2. The Gemini AI Pipeline Configuration
const SYSTEM_PROMPT = `You are an expert Cybersecurity Threat Intelligence API. 
Your sole function is to analyze digital communications (emails, messages, web text) and detect phishing, financial scams, social engineering, and malicious misinformation.

You must analyze the provided user text and return your assessment STRICTLY as a JSON object. Do not include markdown formatting, conversational text, or any other output besides the JSON.

Perform your analysis based on these criteria:
1. HIGH RISK (Score 80-100): Clear malicious intent, credential harvesting, aggressive urgency, suspicious links, or known scam typologies.
2. MEDIUM RISK (Score 40-79): Suspicious elements, unusual requests for information or money, unverified claims, but lacks definitive malicious payload.
3. LOW RISK (Score 0-39): Standard communication, safe marketing, or benign text.

You must explain the "why" behind the threat in your indicators and accurately extract flaggedPhrases from the text.`;

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
      enum: ['Phishing', 'Scam', 'Misinformation', 'Safe']
    },
    indicators: {
      type: 'ARRAY',
      items: { type: 'STRING' },
      description: 'Array of strings explaining the reasoning behind the risk score.'
    },
    flaggedPhrases: {
      type: 'ARRAY',
      items: { type: 'STRING' },
      description: 'Array of exact substrings extracted from the text that indicate danger. Empty if safe.'
    }
  },
  required: ['riskLevel', 'riskScore', 'classification', 'indicators', 'flaggedPhrases']
};

/**
 * 4. Error Handling & Fallback
 * Hardcoded Fallback Heuristics mock response
 */
const getFallbackHeuristics = () => {
  return {
    isMock: true,
    riskLevel: 'LOW',
    riskScore: 0,
    classification: 'Safe',
    indicators: ['Fallback heuristics activated due to AI service unavailability or missing API key.', 'Unable to perform deep threat analysis.'],
    flaggedPhrases: []
  };
};

// POST /api/scan
router.post('/scan', async (req, res) => {
  try {
    const { text, source } = req.body;

    // Basic validation
    if (!text || typeof text !== 'string') {
      return res.status(400).json({ 
        success: false, 
        error: 'Bad Request',
        message: 'Invalid payload: "text" is required.' 
      });
    }

    console.log(`\n--- [${new Date().toISOString()}] Scan Request Received ---`);
    console.log(`Source: ${source || 'Unknown'}`);
    console.log(`Content Length: ${text.length} characters`);
    
    let analysisResult = null;
    let isMock = true;

    // Attempt Gemini AI Analysis
    if (ai) {
      try {
        console.log('Sending payload to Gemini 2.5 Flash for threat analysis...');
        
        const response = await ai.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: text,
          config: {
            systemInstruction: SYSTEM_PROMPT,
            responseMimeType: 'application/json',
            responseSchema: RESPONSE_SCHEMA,
            temperature: 0.1 // Low temperature for deterministic analysis
          }
        });

        if (response.text) {
          analysisResult = JSON.parse(response.text);
          isMock = false;
          console.log(`Gemini Analysis Complete: ${analysisResult.classification} [Risk Score: ${analysisResult.riskScore}]`);
        } else {
          throw new Error('Received empty response from Gemini API');
        }
      } catch (aiError) {
        console.error('Gemini API Request Failed:', aiError);
        // Do not crash; execution will drop down to the fallback block
      }
    }

    // Apply Fallback if Gemini failed or is unconfigured
    if (!analysisResult) {
      console.log('Applying Fallback Mock Heuristics...');
      analysisResult = getFallbackHeuristics();
      isMock = true;
    }

    // 3. The Telemetry Pipeline (Supabase Insertion)
    // Only insert real telemetry data (skip if we used fallback mock data)
    if (!isMock && supabase) {
      try {
        const eventId = crypto.randomUUID();
        const userId = '0c182d52-887f-482e-8b87-12339c971fd5'; // Dummy UUID placeholder
        
        const scanEventRecord = {
          id: eventId,
          user_id: userId,
          source: source || 'unknown',
          threat_category: analysisResult.classification,
          confidence_score: analysisResult.riskScore,
          ai_explanation: analysisResult.indicators.join(' ')
        };

        const { error } = await supabase
          .from('scan_events')
          .insert([scanEventRecord]);

        if (error) {
          console.error('Supabase Insertion Error:', error);
        } else {
          console.log(`Telemetry successfully recorded to Supabase (Event ID: ${eventId})`);
        }
      } catch (telemetryError) {
        console.error('Unexpected error in Telemetry Pipeline:', telemetryError);
      }
    }

    // Return final structured payload to the extension
    return res.json({
      success: true,
      data: {
        analyzedAt: new Date().toISOString(),
        source: source || 'unknown',
        isMock: isMock,
        ...analysisResult
      }
    });

  } catch (error) {
    console.error('Unexpected Server Error in /api/scan:', error);
    
    // Ultimate fallback catch-all to prevent server crash and return safe response
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
