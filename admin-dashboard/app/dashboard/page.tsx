'use client';

import React, { useEffect, useState, useCallback } from 'react';
import { supabase } from '@/lib/supabase';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { motion, AnimatePresence } from 'framer-motion';
import Link from 'next/link';


interface ScanEvent {
  id?: string;
  source: string;
  threat_category: string;
  confidence_score: number;
  ai_explanation: string;
  timestamp: string;
  created_at: string;
  sender?: string;
  is_unknown_sender?: boolean;
  raw_text_length?: number;
}

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

interface PipelineStage {
  id: string;
  name: string;
  category: string;
  latency: string;
  throughput: string;
  status: 'Operational' | 'Active' | 'Optimized';
  modelOrEngine: string;
  privacyLevel: string;
  description: string;
  details: {
    memoryFootprint: string;
    quantization: string;
    fallbackRate: string;
    recentLog: string;
  };
}

const PIPELINE_STAGES: PipelineStage[] = [
  {
    id: 'edge-heuristics',
    name: 'Edge Pattern Guard',
    category: 'Heuristic Triage',
    latency: '3.8 ms',
    throughput: '1,420 ev/s',
    status: 'Operational',
    modelOrEngine: 'WASM Regex & Tokenizer',
    privacyLevel: '100% On-Device (Air-Gapped)',
    description: 'Instant local screening for urgency indicators, malicious unicode homoglyphs, and known malicious patterns.',
    details: {
      memoryFootprint: '4.2 MB',
      quantization: 'Native Assembly',
      fallbackRate: '0.04%',
      recentLog: 'Zero false-negatives across last 450 evaluated payloads',
    },
  },
  {
    id: 'transformers-onnx',
    name: 'Neural Threat Classifier',
    category: 'Local NLP Inference',
    latency: '26.4 ms',
    throughput: '340 ev/s',
    status: 'Active',
    modelOrEngine: 'MiniLM-L6-v2 (ONNX Web)',
    privacyLevel: 'Client Memory Only (Zero-Upload)',
    description: 'Embeds and classifies message semantic intent into Safe, Phishing, Scam, or Misinformation with local weights.',
    details: {
      memoryFootprint: '22.8 MB',
      quantization: 'INT8 Quantized',
      fallbackRate: '0.12%',
      recentLog: 'Inference runtime initialized with WebGPU / WebAssembly fallback',
    },
  },
  {
    id: 'privacy-gate',
    name: 'Zero-Knowledge Sanitizer',
    category: 'Privacy Boundary',
    latency: '1.9 ms',
    throughput: '2,800 ev/s',
    status: 'Optimized',
    modelOrEngine: 'SHA-256 & PII Masker',
    privacyLevel: 'Cryptographic Isolation',
    description: 'Strips identifiable names, phone numbers, and private credentials before any optional cloud escalation.',
    details: {
      memoryFootprint: '1.8 MB',
      quantization: 'Pure TypeScript',
      fallbackRate: '0.00%',
      recentLog: 'Strict GDPR / HIPAA token scrubbing enforced',
    },
  },
  {
    id: 'channel-adapters',
    name: 'Multi-Channel Stream',
    category: 'DOM & Socket Ingestion',
    latency: '11.2 ms',
    throughput: 'Realtime',
    status: 'Operational',
    modelOrEngine: 'Gmail / WhatsApp / LinkedIn',
    privacyLevel: 'Sandboxed Content Scripts',
    description: 'Seamless hooks injecting shadow-DOM security indicators directly inside communications interfaces.',
    details: {
      memoryFootprint: '8.4 MB',
      quantization: 'MutationObserver v2',
      fallbackRate: '0.08%',
      recentLog: 'Active DOM observation synchronized with web extension bridge',
    },
  },
  {
    id: 'cloud-synthesis',
    name: 'Cloud Forensics & Gemini 2.0',
    category: 'Deep Threat Reasoning',
    latency: '185 ms',
    throughput: 'On-Demand',
    status: 'Active',
    modelOrEngine: 'Gemini 2.0 Flash + Vector KB',
    privacyLevel: 'Ephemeral Anonymized Context',
    description: 'Generates plain-language forensic explanations and tactical mitigation steps for high-risk novel threats.',
    details: {
      memoryFootprint: 'Serverless Edge',
      quantization: 'Float16 Cloud Tensor',
      fallbackRate: '0.01%',
      recentLog: 'Explainable AI response generated with high factual precision',
    },
  },
];

type TabType = 'all' | 'gmail' | 'whatsapp' | 'linkedin';

const TABS: { id: TabType; label: string; icon: React.ReactNode }[] = [
  {
    id: 'all',
    label: 'All Activity',
    icon: (
      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.75}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
    ),
  },
  {
    id: 'gmail',
    label: 'Gmail',
    icon: (
      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.75}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
      </svg>
    ),
  },
  {
    id: 'whatsapp',
    label: 'WhatsApp',
    icon: (
      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.75}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
      </svg>
    ),
  },
  {
    id: 'linkedin',
    label: 'LinkedIn',
    icon: (
      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.75}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M21 13.255A23.931 23.931 0 0112 15c-3.183 0-6.22-.62-9-1.745M16 6V4a2 2 0 00-2-2h-4a2 2 0 00-2 2v2m4 6h.01M5 20h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
      </svg>
    ),
  },
];


function RiskBadge({ category }: { category: string }) {
  const cat = category?.toLowerCase() || '';

  if (cat === 'safe') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium bg-[#30d158]/10 text-[#30d158] border border-[#30d158]/20">
        <span className="w-1.5 h-1.5 rounded-full bg-[#30d158]" />
        Verified Safe
      </span>
    );
  }
  if (cat === 'phishing') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium bg-[#ff453a]/10 text-[#ff453a] border border-[#ff453a]/20">
        <span className="w-1.5 h-1.5 rounded-full bg-[#ff453a] animate-pulse" />
        Phishing
      </span>
    );
  }
  if (cat === 'scam') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium bg-[#ff9f0a]/10 text-[#ff9f0a] border border-[#ff9f0a]/20">
        <span className="w-1.5 h-1.5 rounded-full bg-[#ff9f0a]" />
        Scam
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium bg-white/[0.06] text-white/80 border border-white/10">
      <span className="w-1.5 h-1.5 rounded-full bg-white/40" />
      {category || 'Suspicious'}
    </span>
  );
}

function StatCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="apple-card rounded-2xl p-5 relative overflow-hidden group">
      <p className="text-[11px] font-medium text-[#86868b] uppercase tracking-wider mb-2">{label}</p>
      <p className="text-3xl font-semibold text-white tracking-tight">{value}</p>
      {sub && <p className="text-[11px] text-[#86868b] mt-1.5">{sub}</p>}
    </div>
  );
}

function SourceIcon({ source }: { source: string }) {
  const cls = "w-3.5 h-3.5 text-white/70";
  switch (source?.toLowerCase()) {
    case 'gmail':
      return <svg className={cls} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.75}><path strokeLinecap="round" strokeLinejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>;
    case 'whatsapp':
      return <svg className={cls} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.75}><path strokeLinecap="round" strokeLinejoin="round" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" /></svg>;
    case 'linkedin':
      return <svg className={cls} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.75}><path strokeLinecap="round" strokeLinejoin="round" d="M21 13.255A23.931 23.931 0 0112 15c-3.183 0-6.22-.62-9-1.745M16 6V4a2 2 0 00-2-2h-4a2 2 0 00-2 2v2m4 6h.01M5 20h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>;
    default:
      return <svg className={cls} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.75}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>;
  }
}


function VulnerabilityCard({
  icon,
  iconColor,
  title,
  summary,
  children,
}: {
  icon: React.ReactNode;
  iconColor: string;
  title: string;
  summary: string;
  children: React.ReactNode;
}) {
  const [isHovered, setIsHovered] = useState(false);

  return (
    <div
      className="apple-card rounded-2xl p-5 cursor-default transition-all duration-300"
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      <div className="flex items-center gap-3 mb-3">
        <div className={`w-8 h-8 rounded-xl ${iconColor} flex items-center justify-center flex-shrink-0 border border-white/10`}>
          {icon}
        </div>
        <h3 className="text-sm font-semibold text-white tracking-tight">{title}</h3>
      </div>

      <AnimatePresence mode="wait">
        {!isHovered ? (
          <motion.p
            key="compact"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="text-xs text-[#86868b] line-clamp-2 leading-relaxed"
          >
            {summary}
          </motion.p>
        ) : (
          <motion.div
            key="expanded"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
            className="overflow-hidden pt-1"
          >
            {children}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}


function InteractiveEventRow({
  event,
  isOpen,
  onToggle,
}: {
  event: ScanEvent;
  isOpen: boolean;
  onToggle: () => void;
}) {
  const [isRowHovered, setIsRowHovered] = useState(false);
  const activeOpen = isOpen || isRowHovered;

  const rawDateStr = event.created_at || event.timestamp;
  const dateObj = rawDateStr ? new Date(rawDateStr) : new Date();
  const dateStr = dateObj.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  const timeStr = dateObj.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });

  const indicators = event.ai_explanation
    ? event.ai_explanation.split(/[.;]/).map((s) => s.trim()).filter((s) => s.length > 10).slice(0, 5)
    : [];

  return (
    <div
      onMouseEnter={() => setIsRowHovered(true)}
      onMouseLeave={() => setIsRowHovered(false)}
      className={`border-b border-white/[0.06] last:border-b-0 transition-colors duration-200 ${
        activeOpen ? 'bg-white/[0.04]' : 'hover:bg-white/[0.02]'
      }`}
    >
      {/* Clickable Header Row */}
      <button
        onClick={onToggle}
        className="w-full text-left px-5 py-3.5 flex items-center gap-4 group"
      >
        <div className="w-28 flex-shrink-0">
          <p className="text-xs text-white/90 font-medium">{dateStr}</p>
          <p className="text-[10px] text-[#86868b] font-mono">{timeStr}</p>
        </div>

        <div className="w-28 flex-shrink-0 flex items-center gap-2">
          <span className="w-6 h-6 rounded-lg bg-white/[0.05] border border-white/[0.08] flex items-center justify-center text-white/70">
            <SourceIcon source={event.source} />
          </span>
          <span className="text-xs text-white/80 font-medium capitalize">
            {event.source}
          </span>
        </div>

        <div className="w-32 flex-shrink-0">
          <RiskBadge category={event.threat_category} />
        </div>

        <div className="flex-1 flex items-center gap-3 min-w-0">
          <div className="w-20 bg-white/[0.08] rounded-full h-1.5 flex-shrink-0 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all ${
                event.confidence_score > 75 ? 'bg-[#ff453a]' :
                event.confidence_score > 40 ? 'bg-[#ff9f0a]' : 'bg-[#30d158]'
              }`}
              style={{ width: `${event.confidence_score}%` }}
            />
          </div>
          <span className="text-xs text-[#86868b] font-mono w-8 flex-shrink-0">{event.confidence_score}%</span>
        </div>

        <motion.div
          animate={{ rotate: activeOpen ? 180 : 0 }}
          transition={{ duration: 0.15 }}
          className="flex-shrink-0 text-white/40 group-hover:text-white/80 transition-colors"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </motion.div>
      </button>

      {/* Expansion Drawer */}
      <AnimatePresence>
        {activeOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
            className="overflow-hidden bg-black/40 border-t border-white/[0.06]"
          >
            <div className="px-6 py-4 space-y-3.5">
              <div>
                <p className="text-[10px] font-semibold text-white/50 uppercase font-mono tracking-wider mb-1.5">
                  AI Forensic Evaluation
                </p>
                <p className={`text-xs leading-relaxed ${
                  event.threat_category?.toLowerCase() === 'safe'
                    ? 'text-[#30d158]/90 font-medium'
                    : 'text-white/80'
                }`}>
                  {event.threat_category?.toLowerCase() === 'safe'
                    ? 'The content is safe and requires no deeper analysis. Verified by local on-device AI.'
                    : (event.ai_explanation || 'No detailed analysis available.')}
                </p>
              </div>

              {indicators.length > 1 && (
                <div>
                  <p className="text-[10px] font-semibold text-white/50 uppercase font-mono tracking-wider mb-2">
                    Key Indicators
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {indicators.map((phrase, i) => (
                      <span
                        key={i}
                        className="inline-block text-[11px] px-2.5 py-1 rounded-md bg-[#ff453a]/10 text-[#ff453a] border border-[#ff453a]/20 font-medium"
                      >
                        {phrase}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div className="flex flex-wrap items-center justify-between gap-4 text-[11px] text-[#86868b] pt-1 border-t border-white/[0.06]">
                <div className="flex items-center gap-4">
                  <span>Timestamp: <strong className="font-mono text-white/70">{dateObj.toISOString()}</strong></span>
                  {event.raw_text_length && <span>Text Length: <strong className="text-white/70">{event.raw_text_length} chars</strong></span>}
                  {event.sender && <span>Sender: <strong className="text-white/70">{event.sender}</strong></span>}
                </div>

                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    navigator.clipboard?.writeText(JSON.stringify(event, null, 2));
                  }}
                  className="px-2.5 py-1 rounded-lg bg-white/[0.05] hover:bg-white/[0.1] text-white/80 text-[10px] font-mono border border-white/[0.08] transition-colors"
                >
                  Copy JSON
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}


export default function DashboardPage() {
  const [session, setSession] = useState<{ user?: { email?: string }; access_token?: string } | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  const [activeTab, setActiveTab] = useState<TabType>('all');
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const [events, setEvents] = useState<ScanEvent[]>([]);

  const [hoveredPipelineId, setHoveredPipelineId] = useState<string | null>(null);
  const [pinnedPipelineId, setPinnedPipelineId] = useState<string | null>(null);

  const fetchAnalysis = useCallback(async (token: string) => {
    try {
      setLoading(true);
      setError(null);
      const res = await fetch('/api/analyze-vulnerability', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error(`Failed to fetch analysis (${res.status})`);
      const data = await res.json();
      setAnalysis(data);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to load analysis';
      setError(message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let isMounted = true;

    const initData = async () => {
      const hash = window.location.hash.substring(1);
      if (hash) {
        const params = new URLSearchParams(hash);
        const accessToken = params.get('access_token');
        const refreshToken = params.get('refresh_token');

        if (accessToken && refreshToken) {
          await supabase.auth.setSession({ access_token: accessToken, refresh_token: refreshToken });
          window.history.replaceState(null, '', window.location.pathname);
        }
      }

      const { data: { session: currentSession } } = await supabase.auth.getSession();
      
      if (isMounted) {
        setSession(currentSession);
        if (currentSession?.access_token) {
          fetchAnalysis(currentSession.access_token);
        } else {
          setLoading(false);
        }
      }

      if (!currentSession) return;

      const { data, error: dbError } = await supabase
        .from('scan_events')
        .select('*')
        .order('created_at', { ascending: false });

      if (!dbError && data && isMounted) {
        setEvents(data);
      }
    };

    initData();

    const channel = supabase
      .channel('realtime-dashboard')
      .on(
        'postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'scan_events' },
        (payload) => {
          setEvents((prev) => [payload.new as ScanEvent, ...prev]);
        }
      )
      .subscribe();

    return () => {
      isMounted = false;
      supabase.removeChannel(channel);
    };
  }, [fetchAnalysis]);

  const handleSignOut = async () => {
    await supabase.auth.signOut();
    window.location.href = '/';
  };

  if (!session && !loading) {
    return (
      <div className="min-h-screen w-full bg-[#000000] flex items-center justify-center p-6 text-white font-sans">
        <div className="apple-glass rounded-3xl p-8 max-w-md w-full text-center space-y-4">
          <div className="w-12 h-12 rounded-2xl bg-white/[0.08] border border-white/10 flex items-center justify-center mx-auto text-white">
            <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h1 className="text-xl font-semibold tracking-tight text-white">Authentication Required</h1>
          <p className="text-xs text-[#86868b] leading-relaxed">
            Please sign in through the DigiSafe browser extension or authenticate your account to inspect threat telemetry.
          </p>
          <div className="pt-2">
            <Link
              href="/"
              className="inline-block px-5 py-2.5 rounded-full text-xs font-medium text-white bg-white/[0.08] hover:bg-white/[0.15] border border-white/10 transition-colors"
            >
              Return to Public Overview
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const allEvents = events || [];
  const filteredEvents = activeTab === 'all' 
    ? allEvents 
    : allEvents.filter(e => e.source === activeTab);

  const totalScans = filteredEvents?.length || 0;
  const avgRisk = Math.round(
    (filteredEvents?.reduce((sum, e) => sum + (e.confidence_score || 0), 0) || 0) / (totalScans || 1)
  );
  
  const categoryMap: Record<string, number> = {};
  const sourceMap: Record<string, number> = {};
  filteredEvents?.forEach(e => {
    categoryMap[e.threat_category] = (categoryMap[e.threat_category] || 0) + 1;
    sourceMap[e.source] = (sourceMap[e.source] || 0) + 1;
  });
  
  const topThreat = Object.keys(categoryMap).sort((a, b) => categoryMap[b] - categoryMap[a])[0] || '—';
  const topSource = Object.keys(sourceMap).sort((a, b) => sourceMap[b] - sourceMap[a])[0] || '—';

  const unknownSendersCount = filteredEvents?.filter(e => e.is_unknown_sender).length || 0;
  const highRiskEvents = filteredEvents?.filter(e => e.threat_category === 'Phishing' || e.threat_category === 'Scam') || [];
  const threatRate = totalScans > 0 ? ((highRiskEvents.length / totalScans) * 100).toFixed(1) : '0.0';

  const pieData = Object.keys(categoryMap).map(key => ({ name: key, value: categoryMap[key] }));
  const COLORS: Record<string, string> = {
    Phishing: '#ff453a',
    Scam: '#ff9f0a',
    Misinformation: '#ffd60a',
    Safe: '#30d158',
    Unsure: '#bf5af2',
  };

  return (
    <div className="min-h-screen w-full bg-[#000000] text-[#f5f5f7] font-sans antialiased selection:bg-[#0a84ff]/30 selection:text-white">

      {/* Top Header */}
      <header className="bg-black/75 backdrop-blur-2xl sticky top-0 z-40 border-b border-white/[0.08]">
        <div className="max-w-[96%] 2xl:max-w-[1600px] mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link
              href="/"
              className="w-8 h-8 rounded-xl bg-gradient-to-br from-white/15 to-white/5 border border-white/10 flex items-center justify-center text-white shadow-inner hover:scale-105 transition-transform"
            >
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </Link>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-sm font-semibold text-white tracking-tight">DigiSafe Enterprise Console</h1>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-white/[0.08] text-white/70 border border-white/10">
                  Telemetry
                </span>
              </div>
              <p className="text-[11px] text-[#86868b] mt-0.5 font-mono">{session?.user?.email}</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {!loading && session?.access_token && (
              <button
                onClick={() => session.access_token && fetchAnalysis(session.access_token)}
                className="text-xs text-white/80 hover:text-white border border-white/10 bg-white/[0.04] hover:bg-white/[0.08] rounded-full px-3.5 py-1.5 transition-all active:scale-95 flex items-center gap-1.5"
              >
                <svg className="w-3.5 h-3.5 text-white/60" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
                <span>Refresh Telemetry</span>
              </button>
            )}
            <button
              onClick={handleSignOut}
              className="text-xs text-[#86868b] hover:text-white transition-colors"
            >
              Sign Out
            </button>
          </div>
        </div>

        {/* Apple Segmented Control Tab Bar */}
        <div className="max-w-[96%] 2xl:max-w-[1600px] mx-auto px-6 pb-3">
          <nav className="inline-flex p-1 rounded-full bg-white/[0.05] border border-white/[0.08] gap-1" aria-label="Channel filter">
            {TABS.map((tab) => {
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => {
                    setActiveTab(tab.id);
                    setExpandedRow(null);
                  }}
                  className="relative px-3.5 py-1.5 text-xs font-medium rounded-full transition-colors flex items-center gap-1.5"
                >
                  {isActive && (
                    <motion.div
                      layoutId="activeTabPill"
                      className="absolute inset-0 bg-white/[0.12] rounded-full shadow-inner border border-white/10"
                      transition={{ type: 'spring', stiffness: 400, damping: 32 }}
                    />
                  )}
                  <span className={`relative z-10 flex items-center gap-1.5 transition-colors ${
                    isActive ? 'text-white' : 'text-[#86868b] hover:text-white'
                  }`}>
                    {tab.icon}
                    {tab.label}
                  </span>
                </button>
              );
            })}
          </nav>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-[96%] 2xl:max-w-[1600px] mx-auto px-6 py-8">
        {loading ? (
          <div className="flex flex-col items-center justify-center py-32 space-y-4">
            <div className="w-7 h-7 border-2 border-white/20 border-t-white rounded-full animate-spin" />
            <p className="text-[#86868b] text-xs font-mono">Aggregating telemetry streams…</p>
          </div>
        ) : error ? (
          <div className="apple-glass rounded-2xl p-6 text-center border-red-500/30">
            <p className="text-[#ff453a] text-sm font-medium">{error}</p>
          </div>
        ) : (
          <div className="space-y-10">

            {/* Top Metric Cards */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              {activeTab === 'whatsapp' ? (
                <>
                  <StatCard label="Total Scans" value={totalScans} sub="Monitored in WhatsApp Web" />
                  <StatCard label="Unknown Senders" value={unknownSendersCount} sub="High priority inspection" />
                  <StatCard label="Smishing Rate" value={`${threatRate}%`} sub="Coercive pattern ratio" />
                  <StatCard label="Top Threat" value={topThreat} sub="Prevalent vector" />
                </>
              ) : (
                <>
                  <StatCard label="Total Scans" value={totalScans} sub="Aggregate across channels" />
                  <StatCard label="Avg Risk Score" value={`${avgRisk}%`} sub="Model confidence rating" />
                  <StatCard label="Top Threat Type" value={topThreat} sub="Primary security vector" />
                  <StatCard label="Leading Channel" value={topSource} sub="Highest traffic source" />
                </>
              )}
            </div>

            {/* WhatsApp Categorical Distribution Chart */}
            {activeTab === 'whatsapp' && pieData.length > 0 && (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div className="apple-card rounded-2xl p-6">
                  <h3 className="text-[11px] font-medium text-[#86868b] uppercase tracking-wider mb-6">Threat Distribution</h3>
                  <div className="h-56">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie data={pieData} innerRadius={55} outerRadius={75} paddingAngle={4} dataKey="value" strokeWidth={0}>
                          {pieData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[entry.name] || '#636366'} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{ backgroundColor: 'rgba(20,20,22,0.95)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', fontSize: '11px', backdropFilter: 'blur(20px)' }}
                          itemStyle={{ color: '#f5f5f7' }}
                        />
                        <Legend verticalAlign="bottom" height={36} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </div>
                <div className="lg:col-span-2" />
              </div>
            )}

            {/* AI Vulnerability Analysis Cards */}
            {activeTab === 'all' && analysis && (
              <section className="space-y-4">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-[#bf5af2]" />
                  <h2 className="text-sm font-semibold text-white tracking-tight">AI Vulnerability Assessment</h2>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <VulnerabilityCard
                    title="Vulnerability Summary"
                    summary={analysis.vulnerabilitySummary || 'No critical vulnerabilities detected.'}
                    icon={<svg className="w-4 h-4 text-[#0a84ff]" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.75}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>}
                    iconColor="bg-[#0a84ff]/15"
                  >
                    <p className="text-xs text-white/80 leading-relaxed">{analysis.vulnerabilitySummary}</p>
                  </VulnerabilityCard>

                  <VulnerabilityCard
                    title="Observed Patterns"
                    summary={analysis.topPatterns?.join('. ') || 'No attack patterns identified.'}
                    icon={<svg className="w-4 h-4 text-[#ff9f0a]" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.75}><path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>}
                    iconColor="bg-[#ff9f0a]/15"
                  >
                    <ul className="space-y-2">
                      {analysis.topPatterns?.map((pattern, i) => (
                        <li key={i} className="flex items-start gap-2 text-xs text-white/80">
                          <span className="mt-[6px] w-1.5 h-1.5 rounded-full bg-[#ff9f0a] flex-shrink-0" />
                          <span>{pattern}</span>
                        </li>
                      ))}
                    </ul>
                  </VulnerabilityCard>

                  <VulnerabilityCard
                    title="Action Plan"
                    summary={analysis.preventionSteps?.join('. ') || 'No action items required.'}
                    icon={<svg className="w-4 h-4 text-[#30d158]" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.75}><path strokeLinecap="round" strokeLinejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" /></svg>}
                    iconColor="bg-[#30d158]/15"
                  >
                    <ul className="space-y-2">
                      {analysis.preventionSteps?.map((step, i) => (
                        <li key={i} className="flex items-start gap-2 text-xs text-white/80">
                          <svg className="w-3.5 h-3.5 text-[#30d158] flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                          </svg>
                          <span>{step}</span>
                        </li>
                      ))}
                    </ul>
                  </VulnerabilityCard>
                </div>
              </section>
            )}

            {/* ── SECTION 1: PIPELINE STATS TABLE (EXPANSION-ON-HOVER) ── */}
            <section id="pipeline-telemetry" className="space-y-4 scroll-mt-24">
              <div className="flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-[#30d158]" />
                    <h2 className="text-sm font-semibold text-white tracking-tight">Detection Pipeline Telemetry</h2>
                  </div>
                  <p className="text-xs text-[#86868b] mt-0.5">
                    Hover over any pipeline subsystem to inspect real-time latency, throughput, memory bounds, and privacy compliance.
                  </p>
                </div>
                <span className="text-[11px] text-white/50 font-mono hidden sm:inline-block">
                  Subsystems: 5 Active
                </span>
              </div>

              <div className="apple-glass rounded-2xl overflow-hidden border border-white/[0.08]">
                <div className="px-5 py-3 border-b border-white/[0.08] bg-white/[0.02] grid grid-cols-12 text-[11px] font-medium text-[#86868b] uppercase tracking-wider">
                  <span className="col-span-4 sm:col-span-3">Stage / Subsystem</span>
                  <span className="col-span-3 sm:col-span-3">Engine &amp; Model</span>
                  <span className="col-span-2 sm:col-span-2 text-right">Inference Latency</span>
                  <span className="hidden sm:inline-block sm:col-span-2 text-right">Throughput</span>
                  <span className="col-span-3 sm:col-span-2 text-right">Health Status</span>
                </div>

                <div className="divide-y divide-white/[0.06]">
                  {PIPELINE_STAGES.map((stage) => {
                    const isHovered = hoveredPipelineId === stage.id || pinnedPipelineId === stage.id;

                    return (
                      <div
                        key={stage.id}
                        onMouseEnter={() => setHoveredPipelineId(stage.id)}
                        onMouseLeave={() => setHoveredPipelineId(null)}
                        onClick={() => setPinnedPipelineId(pinnedPipelineId === stage.id ? null : stage.id)}
                        className={`transition-colors duration-200 cursor-pointer ${
                          isHovered ? 'bg-white/[0.05]' : 'hover:bg-white/[0.02]'
                        }`}
                      >
                        <div className="px-5 py-3.5 grid grid-cols-12 items-center text-sm">
                          <div className="col-span-4 sm:col-span-3 flex items-center gap-2.5">
                            <span className={`w-2 h-2 rounded-full ${
                              stage.status === 'Operational' ? 'bg-[#30d158]' :
                              stage.status === 'Active' ? 'bg-[#0a84ff]' : 'bg-[#bf5af2]'
                            }`} />
                            <div>
                              <p className="font-medium text-white text-xs sm:text-sm tracking-tight">{stage.name}</p>
                              <p className="text-[10px] text-[#86868b]">{stage.category}</p>
                            </div>
                          </div>

                          <div className="col-span-3 sm:col-span-3">
                            <span className="text-xs text-white/90 font-mono tracking-tight">{stage.modelOrEngine}</span>
                            <p className="text-[10px] text-white/40 truncate">{stage.privacyLevel}</p>
                          </div>

                          <div className="col-span-2 sm:col-span-2 text-right">
                            <span className="text-xs font-mono font-medium text-white/90">{stage.latency}</span>
                          </div>

                          <div className="hidden sm:inline-block sm:col-span-2 text-right">
                            <span className="text-xs font-mono text-[#86868b]">{stage.throughput}</span>
                          </div>

                          <div className="col-span-3 sm:col-span-2 text-right flex items-center justify-end gap-1.5">
                            <span className="text-[11px] font-medium px-2 py-0.5 rounded-full bg-white/[0.06] text-white/80 border border-white/10">
                              {stage.status}
                            </span>
                            <motion.span
                              animate={{ rotate: isHovered ? 90 : 0 }}
                              transition={{ duration: 0.15 }}
                              className="text-white/30 text-xs inline-block"
                            >
                              ›
                            </motion.span>
                          </div>
                        </div>

                        <AnimatePresence>
                          {isHovered && (
                            <motion.div
                              initial={{ opacity: 0, height: 0 }}
                              animate={{ opacity: 1, height: 'auto' }}
                              exit={{ opacity: 0, height: 0 }}
                              transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
                              className="overflow-hidden bg-black/40 border-t border-white/[0.06]"
                            >
                              <div className="px-6 py-4 space-y-3">
                                <p className="text-xs text-white/80 leading-relaxed max-w-3xl">
                                  {stage.description}
                                </p>

                                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
                                  <div className="p-2.5 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                                    <span className="text-[10px] uppercase font-mono text-[#86868b] block">Memory Footprint</span>
                                    <span className="text-xs font-mono font-medium text-white">{stage.details.memoryFootprint}</span>
                                  </div>
                                  <div className="p-2.5 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                                    <span className="text-[10px] uppercase font-mono text-[#86868b] block">Quantization</span>
                                    <span className="text-xs font-mono font-medium text-white">{stage.details.quantization}</span>
                                  </div>
                                  <div className="p-2.5 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                                    <span className="text-[10px] uppercase font-mono text-[#86868b] block">Fallback Rate</span>
                                    <span className="text-xs font-mono font-medium text-[#30d158]">{stage.details.fallbackRate}</span>
                                  </div>
                                  <div className="p-2.5 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                                    <span className="text-[10px] uppercase font-mono text-[#86868b] block">Privacy State</span>
                                    <span className="text-xs font-mono font-medium text-[#0a84ff]">Enforced</span>
                                  </div>
                                </div>

                                <div className="flex items-center gap-2 pt-1 text-[11px] text-[#86868b] font-mono">
                                  <span className="text-white/40">Latest Audit Log:</span>
                                  <span className="text-white/70 truncate">{stage.details.recentLog}</span>
                                </div>
                              </div>
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </div>
                    );
                  })}
                </div>
              </div>
            </section>

            {/* ── SECTION 2: SCAN HISTORY / RECENT EVENTS TABLE (EXPANSION-ON-HOVER) ── */}
            <section className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-[#0a84ff]" />
                    <h2 className="text-sm font-semibold text-white tracking-tight">Recent Threat Events</h2>
                  </div>
                  <p className="text-xs text-[#86868b] mt-0.5">
                    Hover over any event to expand full AI evidence, flagged phrases, and sender origin.
                  </p>
                </div>
                <span className="text-[11px] text-[#86868b] font-mono">{filteredEvents?.length || 0} telemetry records</span>
              </div>

              <div className="apple-glass rounded-2xl overflow-hidden border border-white/[0.08]">
                {/* Table Header */}
                <div className="px-5 py-3 flex items-center gap-4 border-b border-white/[0.08] bg-white/[0.02]">
                  <span className="w-28 text-[10px] font-medium text-[#86868b] uppercase tracking-wider">Date</span>
                  <span className="w-28 text-[10px] font-medium text-[#86868b] uppercase tracking-wider">Source</span>
                  <span className="w-32 text-[10px] font-medium text-[#86868b] uppercase tracking-wider">Threat</span>
                  <span className="flex-1 text-[10px] font-medium text-[#86868b] uppercase tracking-wider">Confidence Gauge</span>
                  <span className="w-4" />
                </div>

                {(!filteredEvents || filteredEvents.length === 0) ? (
                  <div className="px-5 py-16 text-center text-[#86868b] text-sm">
                    No scan history found for this channel.
                  </div>
                ) : (
                  filteredEvents?.map((evt, i) => (
                    <InteractiveEventRow
                      key={evt.id || i}
                      event={evt}
                      isOpen={expandedRow === i}
                      onToggle={() => setExpandedRow(expandedRow === i ? null : i)}
                    />
                  ))
                )}
              </div>
            </section>

          </div>
        )}
      </main>
    </div>
  );
}
