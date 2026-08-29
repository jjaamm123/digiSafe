import { NextRequest, NextResponse } from 'next/server';
import { ai } from '@/lib/gemini';
import { createClient } from '@supabase/supabase-js';
import { ScanRequest, ScanResponse } from '@/types/scan';
import { Type, Schema } from '@google/genai';
import { generateEmbedding, findSimilarThreats } from '@/lib/embeddings';

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '';
const supabase = supabaseUrl && supabaseKey ? createClient(supabaseUrl, supabaseKey) : null;

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

export async function OPTIONS() {
  return NextResponse.json({}, { headers: corsHeaders });
}

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as ScanRequest;
    
    if (!body || typeof body.text !== 'string' || !body.text.trim()) {
      return NextResponse.json({ error: 'Missing or invalid "text" field' }, { status: 400, headers: corsHeaders });
    }

    let scanResponse: ScanResponse | null = null;
    let textEmbedding: number[] | null = null;

    // 1. Try to generate embedding and find similar known threats
    try {
      textEmbedding = await generateEmbedding(body.text);
      
      const similarThreats = await findSimilarThreats(textEmbedding, 0.90, 1);
      
      if (similarThreats.length > 0) {
        const match = similarThreats[0];
        
        // Only reuse if it's considered malicious
        if (match.threat_category !== 'Safe') {
          scanResponse = {
            classification: match.threat_category as ScanResponse['classification'],
            riskScore: match.confidence_score,
            indicators: [match.ai_explanation, 'Matched known threat signature via similarity search.'],
            flaggedPhrases: [], // We might not have exact phrases from cache
            isMock: false,
          };
          console.log(`Matched existing threat signature (${match.similarity} similarity). Bypassing LLM.`);
        }
      }
    } catch (embeddingError: unknown) {
      console.error('Embedding or similarity search error:', embeddingError instanceof Error ? embeddingError.message : embeddingError);
      // Non-fatal, we will just fall back to full LLM scan
    }

    // 2. If no similar threat was found, run full LLM scan
    if (!scanResponse) {
      try {
        if (!ai) {
          throw new Error('Google GenAI SDK is not initialized (missing API key)');
        }

        const responseSchema: Schema = {
          type: Type.OBJECT,
          properties: {
            classification: {
              type: Type.STRING,
              enum: ['Phishing', 'Scam', 'Misinformation', 'Safe'],
            },
            riskScore: {
              type: Type.INTEGER,
              description: 'Risk score from 0 to 100',
            },
            indicators: {
              type: Type.ARRAY,
              items: {
                type: Type.STRING,
              },
            },
            flaggedPhrases: {
              type: Type.ARRAY,
              items: {
                type: Type.STRING,
              },
            },
          },
          required: ['classification', 'riskScore', 'indicators', 'flaggedPhrases'],
        };

        const result = await ai.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: `Analyze the following text for threats, phishing, scams, or misinformation. Be precise and critical. Text to analyze:\n\n${body.text}`,
          config: {
            responseMimeType: 'application/json',
            responseSchema: responseSchema,
          },
        });

        if (!result.text) {
          throw new Error('Empty response from Gemini');
        }

        scanResponse = JSON.parse(result.text);

      } catch (apiError: unknown) {
        console.error('Gemini API Error, falling back to mock:', apiError instanceof Error ? apiError.message : apiError);
        
        // Fallback heuristics
        const textLower = body.text.toLowerCase();
        let classification: ScanResponse['classification'] = 'Safe';
        let riskScore = 0;
        const indicators: string[] = [];
        const flaggedPhrases: string[] = [];

        const phishingRegex = /urgent|verify your account|password|login|click here/i;
        const scamRegex = /winner|lottery|guaranteed return|wire transfer|crypto/i;

        const phishingMatch = textLower.match(phishingRegex);
        const scamMatch = textLower.match(scamRegex);

        if (phishingMatch) {
          classification = 'Phishing';
          riskScore = 80;
          indicators.push('Contains common phishing keywords');
          flaggedPhrases.push(phishingMatch[0]);
        } else if (scamMatch) {
          classification = 'Scam';
          riskScore = 75;
          indicators.push('Contains common scam keywords');
          flaggedPhrases.push(scamMatch[0]);
        }

        scanResponse = {
          classification,
          riskScore,
          indicators,
          flaggedPhrases,
          isMock: true,
        };
      }
    }

    // 3. Database Telemetry
    if (supabase) {
      try {
        let authUserId = null;
        const authHeader = req.headers.get('Authorization');
        
        if (authHeader && authHeader.startsWith('Bearer ')) {
          const token = authHeader.replace('Bearer ', '');
          const { data: { user }, error: authError } = await supabase.auth.getUser(token);
          
          if (!authError && user) {
            authUserId = user.id;
          }
        }

        const { error } = await supabase.from('scan_events').insert({
          user_id: authUserId,
          source: body.source || 'unknown',
          raw_text_length: body.text.length,
          threat_category: scanResponse!.classification,
          confidence_score: scanResponse!.riskScore,
          ai_explanation: scanResponse!.indicators.join('; '),
          timestamp: new Date().toISOString(),
          embedding: textEmbedding ? `[${textEmbedding.join(',')}]` : null, // pgvector format
        });

        if (error) {
          console.error('Supabase telemetry insertion error:', error);
        }
      } catch (dbError) {
        console.error('Supabase telemetry try/catch error:', dbError);
      }
    } else {
      console.warn('Supabase not configured, skipping telemetry.');
    }

    return NextResponse.json(scanResponse, { headers: corsHeaders });
  } catch (error: unknown) {
    console.error('General route error:', error instanceof Error ? error.message : error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500, headers: corsHeaders });
  }
}
