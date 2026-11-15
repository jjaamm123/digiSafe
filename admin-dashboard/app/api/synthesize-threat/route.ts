import { NextRequest, NextResponse } from 'next/server';
import { GoogleGenAI } from '@google/genai';
import { createClient } from '@supabase/supabase-js';
import { BlindThreatDigest } from '@/types/scan';

const apiKey = process.env.GEMINI_API_KEY || '';
const ai = apiKey ? new GoogleGenAI({ apiKey }) : null;

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
    const digest: BlindThreatDigest = await req.json();

    const rawPayload = digest as unknown as Record<string, unknown>;
    if (
      rawPayload.text ||
      rawPayload.rawText ||
      rawPayload.content ||
      rawPayload.body ||
      rawPayload.message ||
      rawPayload.senderEmail ||
      rawPayload.sender ||
      rawPayload.senderName
    ) {
      return NextResponse.json(
        { error: 'Privacy violation: Raw text or sender PII rejected' },
        { status: 400, headers: corsHeaders }
      );
    }

    if (!ai) {
      console.warn('[Gemini Synthesis Fallback] GEMINI_API_KEY not configured.');
      return NextResponse.json(
        { success: false, fallbackRequired: true, error: 'GEMINI_API_KEY not configured' },
        { status: 503, headers: corsHeaders }
      );
    }

    const prompt = `
You are a consumer cybersecurity assistant. Analyze these anonymized numerical/categorical threat indicators from a ${digest.platform} communication:
- Evaluated Risk: ${digest.riskScore}% (${digest.threatCategory})
- Sender Context: ${digest.signals?.isUnknownSender ? 'Unrecognized/Unsaved Contact' : 'Standard Sender'}
- Verified Enterprise Domain: ${digest.signals?.isVerifiedEnterpriseDomain}
- Psychological Urgency Detected: ${digest.signals?.hasUrgencyCoercion} (Primary trigger: "${digest.primaryFlaggedTerm || 'None'}")
- Financial Hooks: ${digest.signals?.hasFinancialHooks}
- Credential Harvesting Risk: ${digest.signals?.hasCredentialHarvesting}
- Link Context: ${digest.metrics?.urlCount ?? 0} total links (${digest.metrics?.suspiciousUrlCount ?? 0} flagged), Host target: "${digest.topTargetDomain || 'None'}"
- Shared Document Vector: ${digest.signals?.hasDocSharingLink}

Task:
Generate a strictly formatted JSON response:
1. "explanation": Exactly 2 clear sentences in plain English (8th-grade reading level) explaining what kind of threat this represents and how the sender is manipulating context, referencing the specific signals provided.
2. "actionableGuidance": Exactly 1 direct sentence instructing the user on what to do next.

Return JSON format: { "explanation": "string", "actionableGuidance": "string" }
`;

    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
      },
    });

    const rawOutput = response.text?.replace(/```(?:json)?/g, '').trim() || '{}';
    const parsed = JSON.parse(rawOutput);

    if (!parsed.explanation) {
      throw new Error('Model response did not contain explanation field');
    }

    if (supabase) {
      try {
        let userId: string | null = null;
        const authHeader = req.headers.get('Authorization');
        if (authHeader && authHeader.startsWith('Bearer ')) {
          const token = authHeader.replace('Bearer ', '');
          const { data: { user } } = await supabase.auth.getUser(token);
          if (user) {
            userId = user.id;
          }
        }

        const scanEventRecord = {
          user_id: userId,
          source: digest.platform || 'unknown',
          sender: 'Redacted (Client-Side Privacy)',
          raw_text_length: digest.metrics?.textLength || 0,
          threat_category: digest.threatCategory,
          confidence_score: digest.riskScore,
          ai_explanation: parsed.explanation,
          created_at: new Date().toISOString(),
          embedding: null,
        };

        const { error: insertError } = await supabase.from('scan_events').insert([scanEventRecord]);
        if (insertError) {
          console.warn('[Supabase Telemetry] Insert warning:', insertError.message);
        }
      } catch (telemetryErr) {
        console.warn('[Supabase Telemetry] Telemetry logging error:', telemetryErr);
      }
    }

    return NextResponse.json(
      {
        success: true,
        source: 'gemini_synthesized',
        explanation: parsed.explanation,
        actionableGuidance: parsed.actionableGuidance,
      },
      { headers: corsHeaders }
    );
  } catch (error: unknown) {
    const err = error as { status?: number; message?: string } | undefined;
    console.warn('[Gemini Synthesis Fallback] API unavailable or quota exceeded:', err?.status || err?.message);
    const isRateLimit =
      err?.status === 429 ||
      err?.message?.includes('429') ||
      err?.message?.toLowerCase().includes('quota') ||
      err?.message?.toLowerCase().includes('rate');

    return NextResponse.json(
      { success: false, fallbackRequired: true, error: err?.message || 'Synthesis failed' },
      { status: isRateLimit ? 429 : 500, headers: corsHeaders }
    );
  }
}
