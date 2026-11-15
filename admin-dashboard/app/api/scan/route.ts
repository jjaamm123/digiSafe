import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import { TelemetryPayload } from '@/types/scan';

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
    const body = (await req.json()) as TelemetryPayload;

    // ── Validate incoming telemetry payload (no raw text accepted) ──
    if (!body || typeof body.threat_category !== 'string' || !body.threat_category.trim()) {
      return NextResponse.json(
        { error: 'Missing or invalid "threat_category" field' },
        { status: 400, headers: corsHeaders }
      );
    }

    if (typeof body.confidence_score !== 'number') {
      return NextResponse.json(
        { error: 'Missing or invalid "confidence_score" field' },
        { status: 400, headers: corsHeaders }
      );
    }

    if (!supabase) {
      console.warn('Supabase not configured, cannot process telemetry.');
      return NextResponse.json(
        { error: 'Internal Server Error' },
        { status: 500, headers: corsHeaders }
      );
    }

    // ── Strict Bearer token authentication (no API key fallback) ──
    const authHeader = req.headers.get('Authorization');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json(
        { error: 'Unauthorized: Missing Authorization header' },
        { status: 401, headers: corsHeaders }
      );
    }

    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);

    if (authError || !user) {
      return NextResponse.json(
        { error: 'Unauthorized: Invalid token' },
        { status: 401, headers: corsHeaders }
      );
    }

    // ── Database Telemetry Insertion ──
    try {
      const scanEventRecord = {
        user_id: user.id,
        source: body.source || 'unknown',
        sender: 'Redacted (Client-Side Privacy)',
        raw_text_length: body.raw_text_length || 0,
        threat_category: body.threat_category,
        confidence_score: body.confidence_score,
        ai_explanation: Array.isArray(body.indicators)
          ? body.indicators.join(' | ')
          : '',
        created_at: new Date().toISOString(),
        // embedding column intentionally left NULL — no vector generation
      };

      const { error } = await supabase.from('scan_events').insert([scanEventRecord]);

      if (error) {
        console.error('Supabase telemetry insertion error:', error);
        return NextResponse.json(
          { success: false, logged: false },
          { status: 500, headers: corsHeaders }
        );
      }
    } catch (dbError) {
      console.error('Supabase telemetry try/catch error:', dbError);
      return NextResponse.json(
        { success: false, logged: false },
        { status: 500, headers: corsHeaders }
      );
    }

    return NextResponse.json(
      { success: true, logged: true },
      { headers: corsHeaders }
    );
  } catch (error: unknown) {
    console.error('General route error:', error instanceof Error ? error.message : error);
    return NextResponse.json(
      { error: 'Internal Server Error' },
      { status: 500, headers: corsHeaders }
    );
  }
}
