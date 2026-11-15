import { supabase } from '@/lib/supabase';
import HomeClient from './HomeClient';

export const dynamic = 'force-dynamic';

export default async function Home() {
  const { data: events, error } = await supabase
    .from('scan_events')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(50);

  if (error) {
    return <div className="p-10 text-red-500">Error fetching data: {error.message}</div>;
  }

  return <HomeClient initialEvents={events || []} />;
}