import { supabase } from '@/lib/supabase';

export default async function Home() {
  // Fetch 50 events so our top-level metrics look realistic
  const { data: events, error } = await supabase
    .from('scan_events')
    .select('*')
    .order('timestamp', { ascending: false })
    .limit(50);

  if (error) {
    return <div className="p-10 text-red-500">Error fetching data: {error.message}</div>;
  }

  // --- Calculate KPI Metrics ---
  const totalScans = events.length;
  // Count threats that aren't safe and have a high AI confidence score
  const criticalThreats = events.filter(e => e.confidence_score > 85 && e.threat_category !== 'safe').length;
  const phishingAttempts = events.filter(e => e.threat_category === 'phishing').length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 p-8 font-sans">
      
      {/* Header Section */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white tracking-tight">Digital Safety Dashboard</h1>
        <p className="text-slate-400 mt-2">Real-time threat monitoring and incident response.</p>
      </div>

      {/* Top Row: KPI Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl shadow-sm">
          <h3 className="text-slate-400 text-sm font-medium uppercase tracking-wider">Total Scans</h3>
          <p className="text-4xl font-bold text-white mt-2">{totalScans}</p>
        </div>
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl shadow-sm">
          <h3 className="text-slate-400 text-sm font-medium uppercase tracking-wider">Critical Threats</h3>
          <p className="text-4xl font-bold text-red-500 mt-2">{criticalThreats}</p>
        </div>
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl shadow-sm">
          <h3 className="text-slate-400 text-sm font-medium uppercase tracking-wider">Phishing Attempts</h3>
          <p className="text-4xl font-bold text-orange-500 mt-2">{phishingAttempts}</p>
        </div>
      </div>

      {/* Bottom Section: Data Investigation Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="px-6 py-5 border-b border-slate-800 bg-slate-900/50">
          <h2 className="text-lg font-semibold text-white">Recent Threat Events</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-950 text-slate-400">
              <tr>
                <th className="px-6 py-4 font-medium">Date</th>
                <th className="px-6 py-4 font-medium">Source</th>
                <th className="px-6 py-4 font-medium">Category</th>
                <th className="px-6 py-4 font-medium">AI Confidence</th>
                <th className="px-6 py-4 font-medium">AI Analysis</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {/* We only render the 10 most recent events in the table */}
              {events.slice(0, 10).map((event) => (
                <tr key={event.id} className="hover:bg-slate-800/40 transition-colors">
                  
                  {/* Date Column */}
                  <td className="px-6 py-4 whitespace-nowrap text-slate-300">
                    {new Date(event.timestamp).toLocaleDateString()}
                  </td>
                  
                  {/* Source Column */}
                  <td className="px-6 py-4 uppercase text-xs font-bold text-slate-500 tracking-wider">
                    {event.source}
                  </td>
                  
                  {/* Dynamic Category Pill Column */}
                  <td className="px-6 py-4">
                    <span className={`px-3 py-1 rounded-full text-xs font-semibold tracking-wide
                      ${event.threat_category === 'safe' ? 'bg-emerald-500/10 text-emerald-400' : ''}
                      ${event.threat_category === 'phishing' ? 'bg-orange-500/10 text-orange-400' : ''}
                      ${event.threat_category === 'scam' ? 'bg-rose-500/10 text-rose-400' : ''}
                      ${event.threat_category === 'misinformation' ? 'bg-amber-500/10 text-amber-400' : ''}
                    `}>
                      {event.threat_category}
                    </span>
                  </td>
                  
                  {/* Confidence Score Visual Bar Column */}
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                        <div 
                          className={`h-full ${event.confidence_score > 80 ? 'bg-rose-500' : 'bg-indigo-500'}`} 
                          style={{ width: `${event.confidence_score}%` }}
                        ></div>
                      </div>
                      <span className="text-slate-400 font-mono">{event.confidence_score}%</span>
                    </div>
                  </td>
                  
                  {/* Explanation Column */}
                  <td className="px-6 py-4 text-slate-400 max-w-xs truncate">
                    {event.ai_explanation}
                  </td>
                  
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      
    </div>
  );
}