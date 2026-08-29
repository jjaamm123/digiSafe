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
  const [session, setSession] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'scanner' | 'dashboard'>('scanner');

  // 1. On mount: check existing session + listen for auth state changes
  useEffect(() => {
    // Check for an existing session on load
    supabase.auth.getSession().then(({ data: { session } }) => {
      console.log('[DigiSafe] Initial session check:', session ? session.user?.email : 'none');
      setSession(session);
      setLoading(false);
    });

    // Listen for the moment the Google OAuth popup finishes
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      console.log('[DigiSafe] Auth state changed:', _event, session?.user?.email);
      setSession(session);
      setLoading(false);
    });

    return () => subscription.unsubscribe();
  }, []);

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [authError, setAuthError] = useState<string | null>(null);

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
        setAuthError('Sign up successful! You can now sign in.');
      }
    } catch (err: any) {
      setAuthError(err.message || 'Failed to sign up');
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
    setLoading(true);
    setAuthError(null);
    try {
      const { data, error } = await supabase.auth.signInWithPassword({ email, password });
      if (error) throw error;
      if (data.session) {
        setSession(data.session);
      }
    } catch (err: any) {
      setAuthError(err.message || 'Failed to sign in');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    await supabase.auth.signOut();
    setSession(null);
  };

  // --- Render ---

  // Loading state
  if (loading) {
    return (
      <div className="w-[380px] min-h-[500px] bg-slate-900 text-slate-100 flex flex-col items-center justify-center font-sans">
        <span className="text-sm font-medium text-slate-400">Loading...</span>
      </div>
    );
  }

  // Login screen
  if (!session) {
    return (
      <div className="w-[380px] min-h-[500px] bg-slate-900 text-slate-100 flex flex-col p-6 font-sans">
        <div className="flex-1 flex flex-col justify-center">
          <h1 className="text-2xl font-bold text-center mb-2">DigiSafe</h1>
          <p className="text-sm text-slate-400 text-center mb-8">Sign in to access your threat intelligence dashboard.</p>
          
          {authError && (
            <div className="mb-4 p-3 bg-red-900/30 border border-red-500/30 text-red-400 text-xs rounded text-center">
              {authError}
            </div>
          )}

          <form className="space-y-4" onSubmit={handleSignIn}>
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500 transition-colors"
                placeholder="you@example.com"
                required
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500 transition-colors"
                placeholder="••••••••"
                required
              />
            </div>
            <div className="pt-2 flex flex-col space-y-3">
              <button
                onClick={handleSignIn}
                type="submit"
                className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded transition-colors text-sm"
              >
                Sign In
              </button>
              <button
                onClick={handleSignUp}
                type="button"
                className="w-full bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-medium py-2 px-4 rounded transition-colors text-sm"
              >
                Create Account
              </button>
            </div>
          </form>
        </div>
      </div>
    );
  }

  // Dashboard (authenticated)
  return (
    <div className="w-[380px] min-h-[500px] bg-slate-900 text-slate-100 flex flex-col font-sans">
      <div className="flex items-center justify-between p-4 bg-slate-900 border-b border-slate-800">
        <div>
          <h1 className="text-lg font-bold text-slate-100">DigiSafe</h1>
          <p className="text-[11px] text-slate-500">{session.user?.email}</p>
        </div>
        <button onClick={handleLogout} className="text-xs text-slate-400 hover:text-slate-200 font-medium">Logout</button>
      </div>
      
      <div className="flex border-b border-slate-800 bg-slate-900">
        <button 
          onClick={() => setActiveTab('scanner')}
          className={`flex-1 py-3 text-sm font-medium ${activeTab === 'scanner' ? 'border-b-2 border-blue-500 text-blue-400' : 'text-slate-400 hover:text-slate-200'}`}
        >
          Scanner
        </button>
        <button 
          onClick={async () => {
            const { data: { session } } = await supabase.auth.getSession();
            if (session) {
              // Pass tokens via URL hash to avoid server-side logging
              const dashboardUrl = `http://localhost:3000/dashboard#access_token=${session.access_token}&refresh_token=${session.refresh_token}`;
              window.open(dashboardUrl, '_blank');
            } else {
              window.open('http://localhost:3000/dashboard', '_blank');
            }
          }}
          className="flex-1 py-3 text-sm font-medium text-slate-400 hover:text-slate-200 flex items-center justify-center gap-1"
        >
          Full Dashboard
          <svg className="w-3 h-3 opacity-60" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
          </svg>
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-4">
        <ScannerTab />
      </div>
    </div>
  );
}

function ScannerTab() {
  return (
    <div className="p-6 flex flex-col items-center text-center">
      <div className="w-16 h-16 bg-blue-900/30 text-blue-400 rounded-full flex items-center justify-center mb-4 border border-blue-500/30">
        <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
      </div>
      <h2 className="text-sm font-semibold text-slate-100 mb-2">Passive Scanner Active</h2>
      <p className="text-xs text-slate-400 leading-relaxed">
        DigiSafe is running in the background. Open a supported platform like Gmail or LinkedIn, and the scan badge will appear on suspicious content.
      </p>
    </div>
  );
}

// Absolute URL required in extension context — relative URLs resolve to chrome-extension://...
const BACKEND_URL = import.meta.env.WXT_BACKEND_URL || 'http://localhost:3000';

function DashboardTab() {
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [assessment, setAssessment] = useState<string | null>(null);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      setError(null);

      const { data: { session } } = await supabase.auth.getSession();
      const token = session?.access_token;

      // Fetch scan events directly from Supabase (no backend needed, no CORS issue)
      const { data: scanEvents, error: dbError } = await supabase
        .from('scan_events')
        .select('*')
        .order('timestamp', { ascending: false })
        .limit(20);

      if (!dbError && scanEvents) {
        setEvents(scanEvents);
      }

      // Fetch AI assessment from backend (absolute URL required in extension context)
      if (token) {
        const res = await fetch(`${BACKEND_URL}/api/assessment`, {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
        });

        if (res.ok) {
          const data = await res.json();
          if (data.assessment) setAssessment(data.assessment);
        } else {
          console.warn('[DigiSafe] Assessment endpoint returned:', res.status);
        }
      }
    } catch (err: any) {
      console.error('[DigiSafe] Dashboard fetch failed:', err);
      setError(err.message || 'Unable to connect to security backend');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="p-6 text-center text-sm text-slate-400">Loading dashboard...</div>;
  }

  return (
    <div className="space-y-4">
      {/* Defensive error banner with retry */}
      {error && (
        <div className="p-3 bg-red-900/40 border border-red-700/50 rounded-lg text-red-200 text-xs flex justify-between items-center">
          <span>Backend unreachable. Ensure it is running on port 3000 or 5000.</span>
          <button
            onClick={fetchDashboardData}
            className="ml-2 underline hover:text-white transition-colors whitespace-nowrap"
          >
            Retry
          </button>
        </div>
      )}

      {assessment && (
        <div className="bg-blue-900/20 border border-blue-500/30 rounded p-4 shadow-sm">
          <h3 className="text-xs font-bold text-blue-400 uppercase tracking-wider mb-2">AI Security Profile</h3>
          <p className="text-sm text-slate-300 leading-relaxed">{assessment}</p>
        </div>
      )}

      <div>
        <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-3">Recent Scans</h3>
        {events.length === 0 ? (
          <p className="text-sm text-slate-500 italic text-center py-4">No scan history found.</p>
        ) : (
          <div className="space-y-2">
            {events.map((evt) => (
              <ScanEventRow key={evt.id} event={evt} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function ScanEventRow({ event }: { event: ScanEvent }) {
  const [expanded, setExpanded] = useState(false);
  
  const date = new Date(event.timestamp).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  const isSafe = event.threat_category === 'Safe';
  const color = isSafe ? 'bg-green-900/30 text-green-400' : event.confidence_score > 70 ? 'bg-red-900/30 text-red-400' : 'bg-yellow-900/30 text-yellow-400';

  return (
    <div className="border border-slate-700 rounded bg-slate-800 overflow-hidden shadow-sm">
      <button 
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left p-3 flex flex-col hover:bg-slate-700/50 transition-colors"
      >
        <div className="flex items-center justify-between w-full">
          <span className="text-sm font-medium text-slate-200 capitalize">{event.source}</span>
          <span className="text-xs text-slate-400">{date}</span>
        </div>
        <div className="flex items-center justify-between w-full mt-1.5">
          <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${color}`}>
            {event.threat_category}
          </span>
          {!isSafe && (
            <span className="text-xs font-semibold text-slate-300">{event.confidence_score}% Risk</span>
          )}
        </div>
      </button>
      
      {expanded && (
        <div className="p-3 bg-slate-900/50 border-t border-slate-700 text-sm text-slate-300 leading-relaxed">
          <strong className="block text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">Analysis</strong>
          {event.ai_explanation || 'No detailed analysis available.'}
        </div>
      )}
    </div>
  );
}
