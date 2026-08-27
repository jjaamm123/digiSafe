-- 1. Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- 2. Add embedding column to existing scan_events table
-- We assume scan_events already exists.
ALTER TABLE scan_events ADD COLUMN IF NOT EXISTS embedding vector(768);

-- 3. Create an HNSW index for fast similarity search
CREATE INDEX IF NOT EXISTS scan_events_embedding_idx 
ON scan_events USING hnsw (embedding vector_cosine_ops);

-- 4. Create an RPC function to match threats
-- This function finds scan events with similar embeddings using cosine similarity.
CREATE OR REPLACE FUNCTION match_threats(
  query_embedding vector(768),
  match_threshold float,
  match_count int
)
RETURNS TABLE(
  id uuid,
  event_id uuid,
  threat_category text,
  confidence_score int,
  ai_explanation text,
  similarity float
)
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN QUERY
  SELECT
    scan_events.id,
    scan_events.event_id,
    scan_events.threat_category,
    scan_events.confidence_score,
    scan_events.ai_explanation,
    1 - (scan_events.embedding <=> query_embedding) AS similarity
  FROM scan_events
  WHERE 1 - (scan_events.embedding <=> query_embedding) > match_threshold
  ORDER BY scan_events.embedding <=> query_embedding
  LIMIT match_count;
END;
$$;
