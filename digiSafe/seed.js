import { createClient } from '@supabase/supabase-js';
import { faker } from '@faker-js/faker';

// TODO: Replace these two strings with your actual Supabase URL and Key
const supabaseUrl = 'https://abmtdxixfbryubdapgow.supabase.co';
const supabaseKey = 'sb_publishable_gJQ-3jcRrkPjzLQ4vCiJIg_RAgyl7LR';
const supabase = createClient(supabaseUrl, supabaseKey);

async function seedDatabase() {
  console.log('🌱 Starting B2C database seed...');

  // 1. Generate 10 Standalone Mock Users
  const usersToInsert = Array.from({ length: 10 }).map(() => ({
    email: faker.internet.email(),
    role: faker.helpers.arrayElement(['user', 'premium_user']),
    vulnerability_index: faker.number.int({ min: 0, max: 100 })
  }));

  const { data: users, error: usersError } = await supabase
    .from('users')
    .insert(usersToInsert)
    .select();

  if (usersError) throw usersError;
  console.log(`✅ Created 10 Standalone Users`);

  // 2. Generate 500 Mock Scan Events tied directly to users
  const events = Array.from({ length: 500 }).map(() => ({
    user_id: faker.helpers.arrayElement(users).id,
    source: faker.helpers.arrayElement(['gmail', 'linkedin', 'sms']),
    threat_category: faker.helpers.arrayElement(['Safe', 'Phishing', 'Scam', 'Misinformation']),
    confidence_score: faker.number.int({ min: 50, max: 99 }),
    ai_explanation: faker.lorem.sentence(),
    timestamp: faker.date.recent({ days: 30 }).toISOString()
  }));

  const { error: eventsError } = await supabase
    .from('scan_events')
    .insert(events);

  if (eventsError) throw eventsError;
  console.log(`✅ Created 500 Mock Scan Events`);
  console.log('🎉 Seeding Complete! Your B2C dashboard has data.');
}

seedDatabase().catch(console.error);