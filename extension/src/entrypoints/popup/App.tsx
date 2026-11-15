import React, { useState, useEffect } from 'react';
import { supabase } from '@/utils/supabase';

interface ScanEvent {
  id: string;
  source: string;
  threat_category: string;
  confidence_score: number;
  ai_explanation: string;
  timestamp: string;
}

export default function App() {
  const [session, setSession] = useState<{ user?: { email?: string }; access_token?: string; refresh_token?: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'scanner' | 'activity'>('scanner');

  useEffect(() => {
    let isMounted = true;

    const safetyTimer = setTimeout(() => {
      if (isMounted) setLoading(false);
    }, 1200);

    const initAuth = async () => {
      try {
        const timeoutPromise = new Promise<{ data: { session: null } }>((resolve) =>
          setTimeout(() => resolve({ data: { session: null } }), 1000)
        );
        const { data } = await Promise.race([supabase.auth.getSession(), timeoutPromise]);
        if (isMounted) {
          setSession(data?.session || null);
        }
      } catch (err) {
        console.warn('[DigiSafe] Initial session check warning:', err);
        if (isMounted) setSession(null);
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    initAuth();

    let unsubscribeFn: (() => void) | null = null;
    try {
      const authListener = supabase.auth.onAuthStateChange((_event, newSession) => {
        if (isMounted) {
          setSession(newSession);
          setLoading(false);
        }
      });
      if (authListener?.data?.subscription) {
        unsubscribeFn = () => authListener.data.subscription.unsubscribe();
      }
    } catch (e) {
      console.warn('[DigiSafe] Auth listener error:', e);
    }

    return () => {
      isMounted = false;
      clearTimeout(safetyTimer);
      if (unsubscribeFn) {
        try {
          unsubscribeFn();
        } catch {}
      }
    };
  }, []);

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [authError, setAuthError] = useState<string | null>(null);
  const [authMode, setAuthMode] = useState<'signin' | 'signup'>('signin');

  const handleSignUp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      setAuthError('Email and password are required');
      return;
    }
    setLoading(true);
    setAuthError(null);
    try {
      const { data, error } = await supabase.auth.signUp({ email, password });
      if (error) throw error;
      if (data.session) {
        setSession(data.session);
      } else {
        setAuthError('Account registered! You can now sign in.');
        setAuthMode('signin');
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to register';
      setAuthError(message);
    } finally {
      setLoading(false);
    }
  };

  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      setAuthError('Email and password are required');
      return;
    }

    if (!import.meta.env.WXT_SUPABASE_URL) {
      setAuthError('Extension misconfigured: Missing Supabase URL in .env.');
      return;
    }

    setLoading(true);
    setAuthError(null);
    try {
      const { data, error } = await supabase.auth.signInWithPassword({ email, password });
      if (error) {
        setAuthError(
          error.message === 'Failed to fetch'
            ? 'Network error: Cannot reach authentication server.'
            : error.message
        );
      } else if (data.session) {
        setSession(data.session);
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Authentication failed';
      setAuthError(message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    await supabase.auth.signOut();
    setSession(null);
  };

  if (loading) {
    return (
      <div className="w-[380px] min-h-[520px] bg-[#000000] text-[#f5f5f7] flex flex-col items-center justify-center font-sans">
        <div className="w-8 h-8 rounded-full border-2 border-white/10 border-t-white animate-spin mb-3" />
        <span className="text-xs font-mono text-[#86868b] tracking-tight">Initializing Core…</span>
      </div>
    );
  }

  if (!session) {
    return (
      <div className="w-[380px] min-h-[520px] bg-[#000000] text-[#f5f5f7] flex flex-col justify-between p-6 font-sans antialiased">
        <div className="pt-4 text-center">
          <div className="w-14 h-14 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-white/15 to-white/5 border border-white/10 flex items-center justify-center shadow-2xl shadow-black">
            <svg className="w-7 h-7 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <h1 className="text-xl font-semibold tracking-tight text-white">DigiSafe</h1>
          <p className="text-xs text-[#86868b] mt-1 max-w-[260px] mx-auto">
            Zero-Knowledge On-Device Threat Interception &amp; Forensic Triage
          </p>
        </div>

        <div className="my-auto py-4">
          {authError && (
            <div className="mb-4 p-3 bg-[#ff453a]/10 border border-[#ff453a]/20 text-[#ff453a] text-xs rounded-xl text-center">
              {authError}
            </div>
          )}

          <form className="space-y-3" onSubmit={authMode === 'signin' ? handleSignIn : handleSignUp}>
            <div>
              <label className="block text-[11px] font-medium text-[#86868b] mb-1">Apple ID or Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-white/[0.04] border border-white/10 rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-white/30 focus:outline-none focus:border-[#0a84ff] focus:ring-1 focus:ring-[#0a84ff] transition-all"
                placeholder="you@example.com"
                required
              />
            </div>
            <div>
              <label className="block text-[11px] font-medium text-[#86868b] mb-1">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-white/[0.04] border border-white/10 rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-white/30 focus:outline-none focus:border-[#0a84ff] focus:ring-1 focus:ring-[#0a84ff] transition-all"
                placeholder="••••••••••••"
                required
              />
            </div>

            <div className="pt-2 space-y-2">
              <button
                type="submit"
                className="w-full bg-white hover:bg-white/90 text-black font-medium py-2.5 px-4 rounded-full transition-all text-xs active:scale-[0.98] shadow-lg shadow-white/5"
              >
                {authMode === 'signin' ? 'Sign In' : 'Create Account'}
              </button>

              <button
                type="button"
                onClick={() => {
                  setAuthMode(authMode === 'signin' ? 'signup' : 'signin');
                  setAuthError(null);
                }}
                className="w-full bg-white/[0.04] hover:bg-white/[0.08] text-white/80 font-medium py-2 px-4 rounded-full border border-white/10 transition-colors text-xs"
              >
                {authMode === 'signin' ? 'New user? Create an account' : 'Already registered? Sign In'}
              </button>
            </div>
          </form>
        </div>

        <div className="text-center pt-2 border-t border-white/[0.06]">
          <p className="text-[10px] text-[#86868b]">Protected by client-side cryptographic isolation.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="w-[380px] min-h-[520px] bg-[#000000] text-[#f5f5f7] flex flex-col font-sans antialiased selection:bg-[#0a84ff]/30">
      
      {/* Top Header */}
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/[0.08] bg-white/[0.02]">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-xl bg-white/[0.08] border border-white/10 flex items-center justify-center text-white shadow-inner">
            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <div>
            <h2 className="text-xs font-semibold text-white tracking-tight">DigiSafe Guard</h2>
            <p className="text-[10px] text-[#86868b] truncate max-w-[170px] font-mono">{session.user?.email}</p>
          </div>
        </div>

        <button
          onClick={handleLogout}
          className="text-[11px] text-[#86868b] hover:text-white transition-colors px-2 py-1 rounded-md hover:bg-white/[0.04]"
        >
          Sign Out
        </button>
      </div>

      {/* Segmented Control Bar */}
      <div className="px-5 py-2.5 border-b border-white/[0.06] flex items-center justify-between bg-black/40">
        <div className="inline-flex p-0.5 rounded-full bg-white/[0.05] border border-white/[0.08] gap-1">
          <button
            onClick={() => setActiveTab('scanner')}
            className={`px-3 py-1 rounded-full text-xs font-medium transition-all ${
              activeTab === 'scanner' ? 'bg-white/[0.14] text-white shadow-inner' : 'text-[#86868b] hover:text-white'
            }`}
          >
            Protection
          </button>
          <button
            onClick={() => setActiveTab('activity')}
            className={`px-3 py-1 rounded-full text-xs font-medium transition-all ${
              activeTab === 'activity' ? 'bg-white/[0.14] text-white shadow-inner' : 'text-[#86868b] hover:text-white'
            }`}
          >
            Activity
          </button>
        </div>

        <button
          onClick={() => {
            const url = session.access_token
              ? `http://localhost:3000/dashboard#access_token=${session.access_token}&refresh_token=${session.refresh_token}`
              : 'http://localhost:3000/dashboard';
            window.open(url, '_blank');
          }}
          className="text-xs text-white/80 hover:text-white font-medium flex items-center gap-1 px-2.5 py-1 rounded-full bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 transition-colors"
        >
          <span>Console</span>
          <svg className="w-3 h-3 text-white/60" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
          </svg>
        </button>
      </div>

      {/* Tab Content Area */}
      <div className="flex-1 overflow-y-auto p-5">
        {activeTab === 'scanner' ? <AppleScannerView /> : <AppleActivityView />}
      </div>
    </div>
  );
}


function AppleScannerView() {
  return (
    <div className="flex flex-col items-center text-center space-y-6 pt-2">
      {/* Concentric Pulse Rings */}
      <div className="relative w-28 h-28 flex items-center justify-center my-2">
        <div className="absolute inset-0 rounded-full border border-[#30d158]/20 animate-ping" style={{ animationDuration: '3s' }} />
        <div className="absolute inset-3 rounded-full border border-[#30d158]/30" />
        <div className="absolute inset-7 rounded-full bg-[#30d158]/5 border border-[#30d158]/40" />
        <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-[#30d158]/20 to-[#30d158]/5 border border-[#30d158]/40 flex items-center justify-center text-[#30d158] shadow-lg shadow-[#30d158]/10">
          <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
      </div>

      <div>
        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#30d158]/10 text-[#30d158] border border-[#30d158]/20 text-xs font-medium mb-2">
          <span className="w-1.5 h-1.5 rounded-full bg-[#30d158] animate-pulse" />
          Active Shield Monitoring
        </div>
        <h3 className="text-base font-semibold text-white tracking-tight">On-Device Protection Active</h3>
        <p className="text-xs text-[#86868b] leading-relaxed max-w-[280px] mx-auto mt-1.5">
          DigiSafe scans incoming messages across Gmail, WhatsApp, and LinkedIn directly inside browser memory.
        </p>
      </div>

      {/* Feature Micro-Cards */}
      <div className="w-full space-y-2 pt-1 text-left">
        <div className="p-3 rounded-2xl bg-white/[0.03] border border-white/[0.06] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <span className="w-6 h-6 rounded-lg bg-white/[0.06] flex items-center justify-center text-white/70 text-xs font-semibold">
              0K
            </span>
            <div>
              <p className="text-xs font-medium text-white/90">Zero-Knowledge Isolation</p>
              <p className="text-[10px] text-[#86868b]">No raw message text leaves this device</p>
            </div>
          </div>
          <span className="text-[10px] font-mono text-[#30d158] bg-[#30d158]/10 px-2 py-0.5 rounded-full">
            Enforced
          </span>
        </div>

        <div className="p-3 rounded-2xl bg-white/[0.03] border border-white/[0.06] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <span className="w-6 h-6 rounded-lg bg-white/[0.06] flex items-center justify-center text-white/70 text-xs">
              ⚡
            </span>
            <div>
              <p className="text-xs font-medium text-white/90">Local Neural Triage</p>
              <p className="text-[10px] text-[#86868b]">HuggingFace ONNX MiniLM runtime</p>
            </div>
          </div>
          <span className="text-[10px] font-mono text-white/70 bg-white/[0.06] px-2 py-0.5 rounded-full">
            ~26ms
          </span>
        </div>
      </div>
    </div>
  );
}


function AppleActivityView() {
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  useEffect(() => {
    const fetchRecent = async () => {
      try {
        setLoading(true);
        const { data } = await supabase
          .from('scan_events')
          .select('*')
          .order('timestamp', { ascending: false })
          .limit(10);
        setEvents(data || []);
      } catch (err) {
        console.warn('Activity fetch err:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchRecent();
  }, []);

  if (loading) {
    return <div className="py-12 text-center text-xs text-[#86868b] font-mono">Loading activity…</div>;
  }

  if (events.length === 0) {
    return (
      <div className="py-16 text-center text-xs text-[#86868b]">
        No recent scan activity recorded.
      </div>
    );
  }

  return (
    <div className="space-y-2.5">
      <div className="flex items-center justify-between text-[11px] text-[#86868b] uppercase tracking-wider font-medium mb-1">
        <span>Recent Events</span>
        <span className="font-mono">{events.length} items</span>
      </div>

      {events.map((evt) => {
        const isExpanded = expandedId === evt.id;
        const isSafe = evt.threat_category?.toLowerCase() === 'safe';
        const dateStr = new Date(evt.timestamp).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });

        return (
          <div
            key={evt.id}
            className="apple-card rounded-2xl overflow-hidden transition-all duration-200 border border-white/[0.08]"
          >
            <button
              onClick={() => setExpandedId(isExpanded ? null : evt.id)}
              className="w-full text-left p-3 flex items-center justify-between hover:bg-white/[0.02] transition-colors"
            >
              <div className="flex items-center gap-2.5">
                <span className={`w-2 h-2 rounded-full ${
                  isSafe ? 'bg-[#30d158]' : evt.confidence_score > 70 ? 'bg-[#ff453a]' : 'bg-[#ff9f0a]'
                }`} />
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-medium text-white capitalize">{evt.source}</span>
                    <span className="text-[10px] text-[#86868b] font-mono">{dateStr}</span>
                  </div>
                  <span className={`text-[10px] font-medium ${
                    isSafe ? 'text-[#30d158]' : evt.confidence_score > 70 ? 'text-[#ff453a]' : 'text-[#ff9f0a]'
                  }`}>
                    {evt.threat_category} {evt.confidence_score ? `(${evt.confidence_score}%)` : ''}
                  </span>
                </div>
              </div>

              <span className="text-xs text-white/40">
                {isExpanded ? '▲' : '▼'}
              </span>
            </button>

            {isExpanded && (
              <div className="px-3.5 pb-3 pt-1 border-t border-white/[0.06] bg-black/40 text-xs space-y-2">
                <p className="text-[10px] uppercase font-mono text-[#86868b]">AI Forensic Analysis</p>
                <p className={`text-[11px] leading-relaxed ${isSafe ? 'text-[#30d158]/90' : 'text-white/80'}`}>
                  {isSafe ? 'Content verified safe by on-device local model triage.' : (evt.ai_explanation || 'Anomaly detected.')}
                </p>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
