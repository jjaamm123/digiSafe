'use client';

import React, { useEffect, useState, useCallback } from 'react';
import { supabase } from '@/lib/supabase';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';

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
  const [session, setSession] = useState<{ user?: { id?: string; email?: string } } | null>(null);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const [hoveredRow, setHoveredRow] = useState<number | null>(null);

  const fetchData = useCallback(async (userId: string) => {
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
  }, []);

  useEffect(() => {
    const init = async () => {
      const { data: { session: currentSession } } = await supabase.auth.getSession();
      setSession(currentSession);
      if (currentSession?.user?.id) {
        fetchData(currentSession.user.id);
      } else {
        setLoading(false);
      }
    };
    init();
  }, [fetchData]);

  if (!session && !loading) {
    return (
      <div className="min-h-screen bg-[#000000] flex items-center justify-center p-6 text-white font-sans">
        <div className="apple-glass rounded-3xl p-8 max-w-md w-full text-center space-y-4">
          <h2 className="text-lg font-semibold text-white">Sign In Required</h2>
          <p className="text-xs text-[#86868b]">Please sign in through the DigiSafe extension to view WhatsApp intelligence.</p>
          <div className="pt-2">
            <Link href="/" className="px-5 py-2.5 rounded-full text-xs font-medium text-white bg-white/[0.08] hover:bg-white/[0.15] border border-white/10 transition-colors inline-block">
              Return Home
            </Link>
          </div>
        </div>
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

  const COLORS: Record<string, string> = {
    Phishing: '#ff453a',
    Scam: '#ff9f0a',
    Misinformation: '#ffd60a',
    Safe: '#30d158',
    Unsure: '#bf5af2',
  };

  return (
    <div className="min-h-screen bg-[#000000] text-[#f5f5f7] font-sans antialiased p-8 selection:bg-[#0a84ff]/30 selection:text-white">
      <div className="max-w-7xl mx-auto space-y-8">
        
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-white/[0.08]">
          <div className="flex items-center gap-3">
            <Link
              href="/dashboard"
              className="w-8 h-8 rounded-xl bg-white/[0.05] border border-white/10 flex items-center justify-center text-white/70 hover:text-white transition-colors"
            >
              ‹
            </Link>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-semibold tracking-tight text-white">WhatsApp &amp; Messaging Intelligence</h1>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-[#30d158]/10 text-[#30d158] border border-[#30d158]/20">
                  Active Shield
                </span>
              </div>
              <p className="text-xs text-[#86868b] mt-0.5">Real-time smishing, unknown sender triage, and QR payload interception.</p>
            </div>
          </div>

          <Link
            href="/dashboard"
            className="text-xs text-[#86868b] hover:text-white border border-white/10 bg-white/[0.04] rounded-full px-3.5 py-1.5 transition-colors"
          >
            All Channels
          </Link>
        </div>
        
        {loading ? (
          <div className="flex flex-col items-center justify-center py-32 space-y-4">
            <div className="w-7 h-7 border-2 border-white/20 border-t-white rounded-full animate-spin" />
            <p className="text-[#86868b] text-xs font-mono">Loading messaging intelligence...</p>
          </div>
        ) : (
          <>
            {/* KPI Metrics */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="apple-card rounded-2xl p-6">
                <p className="text-[11px] text-[#86868b] font-medium uppercase tracking-wider mb-2">Total WhatsApp Scans</p>
                <p className="text-3xl font-semibold text-white tracking-tight">{totalScans}</p>
                <p className="text-[11px] text-[#86868b] mt-1.5">Incoming chats monitored</p>
              </div>
              <div className="apple-card rounded-2xl p-6">
                <p className="text-[11px] text-[#86868b] font-medium uppercase tracking-wider mb-2">High-Risk Threat Rate</p>
                <p className="text-3xl font-semibold text-[#ff453a] tracking-tight">{threatRate}%</p>
                <p className="text-[11px] text-[#86868b] mt-1.5">Urgency &amp; financial fraud vectors</p>
              </div>
              <div className="apple-card rounded-2xl p-6">
                <p className="text-[11px] text-[#86868b] font-medium uppercase tracking-wider mb-2">Unknown Senders Flagged</p>
                <p className="text-3xl font-semibold text-[#ff9f0a] tracking-tight">{unknownNumbersCount}</p>
                <p className="text-[11px] text-[#86868b] mt-1.5">Unsaved contact screening</p>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Categorical Breakdown */}
              <div className="apple-card rounded-2xl p-6">
                <h3 className="text-[11px] font-medium text-[#86868b] uppercase tracking-wider mb-6">Threat Category Mix</h3>
                <div className="h-64">
                  {pieData.length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={pieData}
                          innerRadius={60}
                          outerRadius={80}
                          paddingAngle={4}
                          dataKey="value"
                          strokeWidth={0}
                        >
                          {pieData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[entry.name] || '#636366'} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{ backgroundColor: 'rgba(20,20,22,0.95)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', fontSize: '11px' }}
                          itemStyle={{ color: '#f5f5f7' }}
                        />
                        <Legend verticalAlign="bottom" height={36} />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="h-full flex items-center justify-center text-[#86868b] text-xs">No categorical data available</div>
                  )}
                </div>
              </div>

              {/* Messaging Incident Table with Expansion on Hover */}
              <div className="lg:col-span-2 apple-glass rounded-2xl p-6 overflow-hidden">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-[11px] font-medium text-[#86868b] uppercase tracking-wider">Recent Messaging Incidents</h3>
                  <span className="text-[10px] text-white/40 font-mono">Hover to inspect</span>
                </div>
                
                <div className="overflow-x-auto">
                  <table className="w-full text-sm text-left">
                    <thead>
                      <tr className="border-b border-white/[0.08] text-[11px] font-medium text-[#86868b] uppercase tracking-wider">
                        <th className="px-4 py-3">Sender / Identity</th>
                        <th className="px-4 py-3">Risk Gauge</th>
                        <th className="px-4 py-3 text-right">Classification</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/[0.06]">
                      {events.slice(0, 10).map((evt, idx) => {
                        const isOpen = expandedRow === idx || hoveredRow === idx;
                        const eventDate = new Date(evt.created_at || evt.timestamp || Date.now());

                        return (
                          <React.Fragment key={evt.id || idx}>
                            <tr 
                              className={`transition-colors cursor-pointer ${isOpen ? 'bg-white/[0.04]' : 'hover:bg-white/[0.02]'}`}
                              onMouseEnter={() => setHoveredRow(idx)}
                              onMouseLeave={() => setHoveredRow(null)}
                              onClick={() => setExpandedRow(expandedRow === idx ? null : idx)}
                            >
                              <td className="px-4 py-3.5">
                                <div className="font-medium text-white/90 text-xs">{evt.sender || 'Unknown Origin'}</div>
                                {evt.is_unknown_sender && (
                                  <span className="inline-block mt-1 text-[9px] bg-[#ff9f0a]/15 text-[#ff9f0a] border border-[#ff9f0a]/30 px-1.5 py-0.5 rounded font-mono font-bold tracking-wider">
                                    UNSAVED
                                  </span>
                                )}
                              </td>
                              <td className="px-4 py-3.5">
                                <div className="flex items-center gap-2">
                                  <div className="w-16 h-1.5 bg-white/[0.08] rounded-full overflow-hidden">
                                    <div 
                                      className={`h-full rounded-full ${
                                        evt.confidence_score > 70 ? 'bg-[#ff453a]' :
                                        evt.confidence_score > 40 ? 'bg-[#ff9f0a]' : 'bg-[#30d158]'
                                      }`}
                                      style={{ width: `${evt.confidence_score}%` }}
                                    />
                                  </div>
                                  <span className="text-xs font-mono text-[#86868b]">{evt.confidence_score}%</span>
                                </div>
                              </td>
                              <td className="px-4 py-3.5 text-right">
                                <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium border ${
                                  evt.threat_category === 'Phishing' ? 'bg-[#ff453a]/10 text-[#ff453a] border-[#ff453a]/20' :
                                  evt.threat_category === 'Scam' ? 'bg-[#ff9f0a]/10 text-[#ff9f0a] border-[#ff9f0a]/20' :
                                  evt.threat_category === 'Safe' ? 'bg-[#30d158]/10 text-[#30d158] border-[#30d158]/20' :
                                  'bg-white/[0.06] text-white/80 border-white/10'
                                }`}>
                                  {evt.threat_category}
                                </span>
                              </td>
                            </tr>
                            <AnimatePresence>
                              {isOpen && (
                                <tr>
                                  <td colSpan={3} className="p-0">
                                    <motion.div
                                      initial={{ opacity: 0, height: 0 }}
                                      animate={{ opacity: 1, height: 'auto' }}
                                      exit={{ opacity: 0, height: 0 }}
                                      transition={{ duration: 0.2 }}
                                      className="overflow-hidden bg-black/40 border-b border-white/[0.06] px-5 py-3 space-y-2"
                                    >
                                      <p className="text-[10px] text-white/50 uppercase font-mono tracking-wider font-semibold">AI Explanation</p>
                                      <p className="text-xs text-white/80 leading-relaxed">{evt.ai_explanation || 'No forensic breakdown available.'}</p>
                                      <p className="text-[10px] text-[#86868b] font-mono">
                                        Scanned: {eventDate.toLocaleString()}
                                      </p>
                                    </motion.div>
                                  </td>
                                </tr>
                              )}
                            </AnimatePresence>
                          </React.Fragment>
                        );
                      })}
                      {events.length === 0 && (
                        <tr>
                          <td colSpan={3} className="px-4 py-12 text-center text-[#86868b] text-xs italic">
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
