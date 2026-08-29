'use client';

import { useEffect, useState } from 'react';
import { supabase } from '@/lib/supabase';

interface AnalysisResult {
  vulnerabilitySummary: string;
  topPatterns: string[];
  preventionSteps: string[];
  telemetry: ScanEvent[];
  meta: {
    totalScans: number;
    avgRisk: number;
    categoryCounts: Record<string, number>;
    sourceCounts: Record<string, number>;
  };
}

interface ScanEvent {
  source: string;
  threat_category: string;
  confidence_score: number;
  ai_explanation: string;
  timestamp: string;
}

function RiskBadge({ category }: { category: string }) {
  const styles: Record<string, string> = {
    Phishing: 'bg-red-900/40 text-red-400 border border-red-500/30',
    Scam: 'bg-orange-900/40 text-orange-400 border border-orange-500/30',
    Misinformation: 'bg-yellow-900/40 text-yellow-400 border border-yellow-500/30',
    Safe: 'bg-green-900/40 text-green-400 border border-green-500/30',
  };
  return (
    <span className={`text-[11px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${styles[category] || 'bg-slate-700 text-slate-300'}`}>
      {category}
    </span>
  );
}

function StatCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-5 backdrop-blur-sm">
      <p className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-1">{label}</p>
      <p className="text-3xl font-bold text-slate-100">{value}</p>
      {sub && <p className="text-xs text-slate-500 mt-1">{sub}</p>}
    </div>
  );
}

export default function DashboardPage() {
  const [session, setSession] = useState<any>(null);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const initSession = async () => {
      // Token Bridge: receive tokens passed via URL hash from the extension popup
      const hash = window.location.hash.substring(1);
      if (hash) {
        const params = new URLSearchParams(hash);
        const accessToken = params.get('access_token');
        const refreshToken = params.get('refresh_token');

        if (accessToken && refreshToken) {
          // Establish the session in this tab's Supabase client
          await supabase.auth.setSession({ access_token: accessToken, refresh_token: refreshToken });
          // Clean the tokens from the URL bar without triggering a reload
          window.history.replaceState(null, '', window.location.pathname);
        }
      }

      // Now check the session (either just set from hash or pre-existing)
      const { data: { session } } = await supabase.auth.getSession();
      setSession(session);
      if (session) {
        fetchAnalysis(session.access_token);
      } else {
        setLoading(false);
      }
    };

    initSession();
  }, []);

  const fetchAnalysis = async (token: string) => {
    try {
      setLoading(true);
      setError(null);
      const res = await fetch('/api/analyze-vulnerability', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error(`Failed to fetch analysis (${res.status})`);
      const data = await res.json();
      setAnalysis(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load analysis');
    } finally {
      setLoading(false);
    }
  };

  const handleSignOut = async () => {
    await supabase.auth.signOut();
    window.location.href = '/';
  };

  if (!session && !loading) {
    return (
      <div className="min-h-screen w-full bg-slate-900 flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-slate-100 mb-2">Authentication Required</h1>
          <p className="text-slate-400 text-sm">Sign in through the DigiSafe extension to view your dashboard.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen w-full bg-slate-900 text-slate-100 font-sans">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-8 py-4 flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-slate-100">DigiSafe Threat Intelligence Center</h1>
            <p className="text-xs text-slate-500 mt-0.5">{session?.user?.email}</p>
          </div>
          <div className="flex items-center gap-4">
            {!loading && session && (
              <button
                onClick={() => fetchAnalysis(session.access_token)}
                className="text-xs text-slate-400 hover:text-slate-200 border border-slate-700 rounded px-3 py-1.5 transition-colors"
              >
                Refresh Analysis
              </button>
            )}
            <button
              onClick={handleSignOut}
              className="text-xs text-slate-400 hover:text-slate-200 font-medium"
            >
              Sign Out
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-8 py-8 space-y-8">
        {loading ? (
          <div className="flex flex-col items-center justify-center py-32 space-y-4">
            <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
            <p className="text-slate-400 text-sm">Running AI vulnerability analysis...</p>
          </div>
        ) : error ? (
          <div className="bg-red-900/20 border border-red-500/30 rounded-xl p-6 text-center">
            <p className="text-red-400 font-medium">{error}</p>
          </div>
        ) : analysis ? (
          <>
            {/* Stats Row */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <StatCard label="Total Scans" value={analysis?.meta?.totalScans || 0} />
              <StatCard label="Avg Risk Score" value={`${analysis?.meta?.avgRisk || 0}%`} />
              <StatCard
                label="Top Threat"
                value={analysis?.meta?.categoryCounts ? Object.entries(analysis.meta.categoryCounts).sort((a, b) => b[1] - a[1])[0]?.[0] ?? '—' : 'Analyzing...'}
              />
              <StatCard
                label="Top Source"
                value={analysis?.meta?.sourceCounts ? Object.entries(analysis.meta.sourceCounts).sort((a, b) => b[1] - a[1])[0]?.[0] ?? '—' : 'Analyzing...'}
              />
            </div>

            {/* AI Analysis Cards */}
            <section>
              <h2 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-4">AI Vulnerability Analysis</h2>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* Card 1: Vulnerability Summary */}
                <div className="bg-slate-800/60 border border-blue-500/20 rounded-xl p-6 backdrop-blur-sm">
                  <div className="flex items-center gap-2 mb-3">
                    <div className="w-8 h-8 rounded-lg bg-blue-900/40 border border-blue-500/30 flex items-center justify-center flex-shrink-0">
                      <svg className="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                      </svg>
                    </div>
                    <h3 className="text-sm font-semibold text-slate-200">Vulnerability Summary</h3>
                  </div>
                  <p className="text-sm text-slate-300 leading-relaxed">{analysis.vulnerabilitySummary}</p>
                </div>

                {/* Card 2: Observed Patterns */}
                <div className="bg-slate-800/60 border border-amber-500/20 rounded-xl p-6 backdrop-blur-sm">
                  <div className="flex items-center gap-2 mb-3">
                    <div className="w-8 h-8 rounded-lg bg-amber-900/40 border border-amber-500/30 flex items-center justify-center flex-shrink-0">
                      <svg className="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    </div>
                    <h3 className="text-sm font-semibold text-slate-200">Observed Patterns</h3>
                  </div>
                  <ul className="space-y-2.5">
                    {analysis.topPatterns.map((pattern, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                        <span className="mt-2 w-1.5 h-1.5 rounded-full bg-amber-400 flex-shrink-0" />
                        {pattern}
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Card 3: Action Plan */}
                <div className="bg-slate-800/60 border border-emerald-500/20 rounded-xl p-6 backdrop-blur-sm">
                  <div className="flex items-center gap-2 mb-3">
                    <div className="w-8 h-8 rounded-lg bg-emerald-900/40 border border-emerald-500/30 flex items-center justify-center flex-shrink-0">
                      <svg className="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
                      </svg>
                    </div>
                    <h3 className="text-sm font-semibold text-slate-200">Action Plan</h3>
                  </div>
                  <ul className="space-y-2.5">
                    {analysis.preventionSteps.map((step, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                        <svg className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                        </svg>
                        {step}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </section>

            {/* Telemetry Table */}
            <section>
              <h2 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-4">
                Scan History <span className="text-slate-600 font-normal normal-case tracking-normal">({analysis.telemetry.length} records)</span>
              </h2>
              <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl overflow-hidden backdrop-blur-sm">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-slate-700/50 bg-slate-800/80">
                        <th className="text-left text-xs font-semibold text-slate-500 uppercase tracking-wider px-5 py-3">Date</th>
                        <th className="text-left text-xs font-semibold text-slate-500 uppercase tracking-wider px-5 py-3">Source</th>
                        <th className="text-left text-xs font-semibold text-slate-500 uppercase tracking-wider px-5 py-3">Threat</th>
                        <th className="text-left text-xs font-semibold text-slate-500 uppercase tracking-wider px-5 py-3">Confidence</th>
                        <th className="text-left text-xs font-semibold text-slate-500 uppercase tracking-wider px-5 py-3">Analysis</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-700/30">
                      {analysis.telemetry.length === 0 ? (
                        <tr>
                          <td colSpan={5} className="px-5 py-8 text-center text-slate-500 text-sm italic">
                            No scan history found.
                          </td>
                        </tr>
                      ) : (
                        analysis.telemetry.map((evt, i) => (
                          <tr key={i} className="hover:bg-slate-700/20 transition-colors">
                            <td className="px-5 py-3 text-xs text-slate-400 whitespace-nowrap">
                              {new Date(evt.timestamp).toLocaleDateString(undefined, {
                                month: 'short', day: 'numeric', year: 'numeric',
                              })}
                            </td>
                            <td className="px-5 py-3 text-xs text-slate-300 capitalize font-medium">{evt.source}</td>
                            <td className="px-5 py-3">
                              <RiskBadge category={evt.threat_category} />
                            </td>
                            <td className="px-5 py-3 text-xs text-slate-300">
                              <div className="flex items-center gap-2">
                                <div className="w-16 bg-slate-700 rounded-full h-1.5">
                                  <div
                                    className={`h-1.5 rounded-full ${
                                      evt.confidence_score > 70 ? 'bg-red-500' :
                                      evt.confidence_score > 40 ? 'bg-yellow-500' : 'bg-green-500'
                                    }`}
                                    style={{ width: `${evt.confidence_score}%` }}
                                  />
                                </div>
                                <span className="text-slate-400">{evt.confidence_score}%</span>
                              </div>
                            </td>
                            <td className="px-5 py-3 text-xs text-slate-400 max-w-xs truncate" title={evt.ai_explanation}>
                              {evt.ai_explanation || '—'}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </section>
          </>
        ) : null}
      </main>
    </div>
  );
}
