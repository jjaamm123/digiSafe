-- Drop the existing tables to cleanly rebuild the schema
DROP TABLE IF EXISTS scan_events;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS organizations;

-- 1. Create the simplified Users table (B2C)
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL UNIQUE,
  role TEXT DEFAULT 'user',
  vulnerability_index INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- 2. Create the Scan Events table linked directly to users
CREATE TABLE scan_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  source TEXT NOT NULL,
  threat_category TEXT NOT NULL,
  confidence_score INTEGER NOT NULL,
  ai_explanation TEXT,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);
