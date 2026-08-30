'use client';

import { useEffect, useState } from 'react';
import { supabase } from '@/lib/supabase';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';

interface ScanEvent {
  id: string;
  source: string;
  threat_category: string;
  confidence_score: number;
  ai_explanation: string;
  sender: string;
  is_unknown_sender: boolean;
  timestamp: string;
  created_at: string;
}

export default function WhatsAppDashboard() {
  const [session, setSession] = useState<any>(null);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedRow, setExpandedRow] = useState<number | null>(null);

  useEffect(() => {
    const init = async () => {
      const { data: { session } } = await supabase.auth.getSession();
      setSession(session);
      if (session) {
        fetchData(session.user.id);
      } else {
        setLoading(false);
      }
    };
    init();
  }, []);

  const fetchData = async (userId: string) => {
    try {
      setLoading(true);
      const { data, error } = await supabase
        .from('scan_events')
        .select('*')
        .eq('user_id', userId)
        .eq('source', 'whatsapp')
        .order('created_at', { ascending: false });
        
      if (error) throw error;
      setEvents(data || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  if (!session && !loading) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center p-4">
        <p className="text-slate-100">Please sign in to view this page.</p>
      </div>
    );
  }

  const totalScans = events.length;
  const highRiskEvents = events.filter(e => e.threat_category === 'Phishing' || e.threat_category === 'Scam');
  const threatRate = totalScans > 0 ? ((highRiskEvents.length / totalScans) * 100).toFixed(1) : '0.0';
  const unknownNumbersCount = events.filter(e => e.is_unknown_sender).length;

  const categoryMap: Record<string, number> = {};
  events.forEach(e => {
    categoryMap[e.threat_category] = (categoryMap[e.threat_category] || 0) + 1;
  });
  const pieData = Object.keys(categoryMap).map(key => ({ name: key, value: categoryMap[key] }));

  const COLORS = {
    Phishing: '#ef4444',
    Scam: '#f97316',
    Misinformation: '#eab308',
    Safe: '#22c55e',
    Unsure: '#f59e0b'
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-8 font-sans">
      <div className="max-w-7xl mx-auto space-y-8">
        <h1 className="text-2xl font-bold border-b border-slate-800 pb-4">WhatsApp & Messaging Intelligence</h1>
        
        {loading ? (
          <div className="flex flex-col items-center justify-center py-32 space-y-4">
            <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
            <p className="text-slate-400 text-sm">Loading intelligence metrics...</p>
          </div>
        ) : (
          <>
            {/* KPI Metrics */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-6 backdrop-blur-sm">
                <p className="text-xs text-slate-400 font-semibold uppercase tracking-wider mb-2">Total WhatsApp Scans</p>
                <p className="text-3xl font-bold text-slate-100">{totalScans}</p>
              </div>
              <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-6 backdrop-blur-sm">
                <p className="text-xs text-slate-400 font-semibold uppercase tracking-wider mb-2">High-Risk Threat Rate</p>
                <p className="text-3xl font-bold text-slate-100">{threatRate}%</p>
              </div>
              <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-6 backdrop-blur-sm">
                <p className="text-xs text-slate-400 font-semibold uppercase tracking-wider mb-2">Unknown Numbers Flagged</p>
                <p className="text-3xl font-bold text-slate-100">{unknownNumbersCount}</p>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Categorical Breakdown */}
              <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-6 backdrop-blur-sm">
                <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-6">Threat Category Mix</h3>
                <div className="h-64">
                  {pieData.length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={pieData}
                          innerRadius={60}
                          outerRadius={80}
                          paddingAngle={5}
                          dataKey="value"
                        >
                          {pieData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[entry.name as keyof typeof COLORS] || '#64748b'} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }} itemStyle={{ color: '#f8fafc' }} />
                        <Legend verticalAlign="bottom" height={36}/>
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="h-full flex items-center justify-center text-slate-500 text-sm">No categorical data available</div>
                  )}
                </div>
              </div>

              {/* Messaging Incident Table */}
              <div className="lg:col-span-2 bg-slate-800/60 border border-slate-700/50 rounded-xl p-6 backdrop-blur-sm overflow-hidden">
                <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-6">Recent Messaging Incidents</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm text-left">
                    <thead>
                      <tr className="border-b border-slate-700/50 bg-slate-800/80">
                        <th className="px-5 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider">Sender / Phone Number</th>
                        <th className="px-5 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider">Risk Score</th>
                        <th className="px-5 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider">Threat Classification</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-700/30">
                      {events.slice(0, 10).map((evt, idx) => (
                        <React.Fragment key={idx}>
                          <tr 
                            className="hover:bg-slate-700/20 transition-colors cursor-pointer"
                            onClick={() => setExpandedRow(expandedRow === idx ? null : idx)}
                          >
                            <td className="px-5 py-3">
                              <div className="font-medium text-slate-300">{evt.sender || 'Unknown'}</div>
                              {evt.is_unknown_sender && (
                                <span className="inline-block mt-1 text-[10px] bg-amber-900/40 text-amber-500 border border-amber-500/30 px-1.5 py-0.5 rounded uppercase font-bold tracking-wider">
                                  Unknown Sender
                                </span>
                              )}
                            </td>
                            <td className="px-5 py-3">
                              <div className="flex items-center gap-2">
                                <span className="w-8 text-slate-400">{evt.confidence_score}%</span>
                                <div className="flex-1 h-1.5 bg-slate-700 rounded-full max-w-[80px]">
                                  <div 
                                    className={`h-full rounded-full ${
                                      evt.confidence_score > 70 ? 'bg-red-500' :
                                      evt.confidence_score > 40 ? 'bg-yellow-500' : 'bg-green-500'
                                    }`}
                                    style={{ width: `${evt.confidence_score}%` }}
                                  />
                                </div>
                              </div>
                            </td>
                            <td className="px-5 py-3">
                              <span className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wider border ${
                                evt.threat_category === 'Phishing' ? 'bg-red-900/40 text-red-400 border-red-500/30' :
                                evt.threat_category === 'Scam' ? 'bg-orange-900/40 text-orange-400 border-orange-500/30' :
                                evt.threat_category === 'Safe' ? 'bg-green-900/40 text-green-400 border-green-500/30' :
                                'bg-slate-700 text-slate-300 border-slate-600'
                              }`}>
                                {evt.threat_category}
                              </span>
                            </td>
                          </tr>
                          {expandedRow === idx && (
                            <tr className="bg-slate-800/80">
                              <td colSpan={3} className="px-5 py-4 border-b border-slate-700/50">
                                <p className="text-xs text-slate-400 mb-1 font-semibold uppercase tracking-wider">AI Explanation</p>
                                <p className="text-sm text-slate-300 mb-2">{evt.ai_explanation || 'No explanation provided.'}</p>
                                <p className="text-xs text-slate-500">
                                  Scanned at: {new Date(evt.created_at || evt.timestamp).toLocaleString()}
                                </p>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      ))}
                      {events.length === 0 && (
                        <tr>
                          <td colSpan={3} className="px-5 py-8 text-center text-slate-500 text-sm italic">
                            No recent messaging incidents found.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
