import { NextRequest, NextResponse } from 'next/server';
import { ai } from '@/lib/gemini';
import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '';
const supabase = supabaseUrl && supabaseKey ? createClient(supabaseUrl, supabaseKey) : null;

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

export async function OPTIONS() {
  return NextResponse.json({}, { headers: corsHeaders });
}

export async function GET(req: NextRequest) {
  try {
    if (!supabase) {
      return NextResponse.json({ error: 'Supabase not configured' }, { status: 500, headers: corsHeaders });
    }

    const authHeader = req.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });
    }

    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);

    if (authError || !user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });
    }

    const { data: scanEvents, error: dbError } = await supabase
      .from('scan_events')
      .select('source, threat_category, confidence_score, ai_explanation, timestamp')
      .eq('user_id', user.id)
      .order('timestamp', { ascending: false })
      .limit(50);

    if (dbError) {
      throw new Error(`Database error: ${dbError.message}`);
    }

    if (!scanEvents || scanEvents.length === 0) {
      return NextResponse.json({ assessment: 'No historical scan data available to generate a profile.' }, { headers: corsHeaders });
    }

    if (!ai) {
      return NextResponse.json({ assessment: 'AI model not configured to generate profile.' }, { headers: corsHeaders });
    }

    const eventSummaries = scanEvents.map(e => `[${e.source}] ${e.threat_category} (${e.confidence_score}% risk): ${e.ai_explanation}`).join('\n');

    const prompt = `You are a cybersecurity analyst. Review this user's threat history and provide a concise, exactly 3-sentence professional security profile identifying their most common threat vectors and actionable advice. Do not use markdown or emojis.

User Scan History:
${eventSummaries}`;

    const result = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: prompt,
      config: {
        temperature: 0.2, // low temperature for professional, consistent tone
      },
    });

    const assessmentText = result.text?.trim() || 'Could not generate an assessment.';

    return NextResponse.json({ assessment: assessmentText }, { headers: corsHeaders });

  } catch (error: unknown) {
    console.error('Assessment route error:', error instanceof Error ? error.message : error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500, headers: corsHeaders });
  }
}
