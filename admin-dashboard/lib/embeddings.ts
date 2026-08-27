import { ai } from './gemini';
import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '';
const supabase = supabaseUrl && supabaseKey ? createClient(supabaseUrl, supabaseKey) : null;

/**
 * Generates an embedding for the given text using Gemini's text-embedding-004 model.
 */
export async function generateEmbedding(text: string): Promise<number[]> {
  if (!ai) {
    throw new Error('Google GenAI SDK is not initialized (missing API key)');
  }

  const response = await ai.models.embedContent({
    model: 'embedding-001',
    contents: text,
  });

  if (!response.embeddings || response.embeddings.length === 0) {
    throw new Error('No embedding returned from Gemini');
  }
  
  const embedding = response.embeddings[0].values;
  if (!embedding) {
    throw new Error('Embedding values are empty');
  }

  return embedding;
}

/**
 * Interface representing a matched threat from the database.
 */
export interface MatchedThreat {
  id: string;
  threat_category: string;
  confidence_score: number;
  ai_explanation: string;
  similarity: number;
}

/**
 * Finds similar threats by querying the match_threats RPC in Supabase.
 */
export async function findSimilarThreats(
  embedding: number[],
  threshold = 0.85,
  limit = 5
): Promise<MatchedThreat[]> {
  if (!supabase) {
    console.warn('Supabase not configured, cannot perform similarity search.');
    return [];
  }

  const { data, error } = await supabase.rpc('match_threats', {
    query_embedding: embedding,
    match_threshold: threshold,
    match_count: limit,
  });

  if (error) {
    console.error('Error fetching similar threats:', error);
    throw error;
  }

  return data as MatchedThreat[];
}
