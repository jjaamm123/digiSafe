import React, { useState, useEffect } from 'react';

export interface ThreatData {
  classification: 'Phishing' | 'Scam' | 'Misinformation' | 'Safe';
  riskScore: number;
  indicators: string[];
  flaggedPhrases: string[];
  isMock?: boolean;
}

interface Props {
  data: ThreatData | null;
  loading: boolean;
  error?: string | null;
  onScan?: () => void;
  onClose: () => void;
}

export function ThreatReportModal({ data, loading, error, onScan, onClose }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [isOpen, setIsOpen] = useState(false); // Controls modal vs button state

  useEffect(() => {
    if (data && !loading && !error) {
      setIsOpen(true);
    } else if (!data) {
      setIsOpen(false);
    }
  }, [data, loading, error]);

  if (!isOpen) {
    if (error) {
      return (
        <button
          onClick={() => setIsOpen(true)}
          className="fixed bottom-6 right-6 z-[9999] bg-red-600 hover:bg-red-700 text-white rounded-full px-4 py-3 shadow-2xl flex items-center transition-all transform hover:scale-105 border border-red-400/30"
        >
          <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <span className="text-sm font-semibold tracking-wide">Offline / Reconnect</span>
        </button>
      );
    }

    return (
      <button
        onClick={() => {
          if (!data && onScan) {
            onScan();
          } else if (data) {
            setIsOpen(true);
          }
        }}
        disabled={loading}
        className={`fixed bottom-6 right-6 z-[9999] ${loading ? 'bg-blue-800 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700 hover:scale-105'} text-white rounded-full px-4 py-3 shadow-2xl flex items-center transition-all transform border border-blue-400/30`}
      >
        {loading ? (
          <>
            <svg className="animate-spin -ml-1 mr-2 h-5 w-5 text-white" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <span className="text-sm font-semibold tracking-wide">Scanning...</span>
          </>
        ) : (
          <>
            <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
            <span className="text-sm font-semibold tracking-wide">{data ? 'Threat Report' : 'Scan Email'}</span>
          </>
        )}
      </button>
    );
  }

  if (loading) {
    return (
      <div className="fixed bottom-6 right-6 z-[9999] w-80 rounded-xl bg-white/20 backdrop-blur-md border border-white/30 shadow-2xl p-4 font-sans text-gray-800">
        <div className="animate-pulse flex flex-col space-y-4">
          <div className="h-4 bg-gray-300 rounded w-1/2"></div>
          <div className="h-2 bg-gray-300 rounded w-full"></div>
          <div className="h-2 bg-gray-300 rounded w-3/4"></div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="fixed bottom-6 right-6 z-[9999] w-80 rounded-2xl bg-white/90 backdrop-blur-xl border border-red-200/50 shadow-2xl overflow-hidden font-sans text-gray-800 transition-all">
        <div className="p-4 border-b border-red-100 flex justify-between items-center bg-red-50/50">
          <div className="flex items-center space-x-2">
            <span className="font-bold text-lg tracking-tight text-red-900">Scan Error</span>
          </div>
          <div className="flex items-center space-x-1">
            <button onClick={() => setIsOpen(false)} className="text-gray-400 hover:text-gray-600 transition-colors p-1" title="Minimize">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
            </button>
            <button onClick={onClose} className="text-gray-400 hover:text-red-500 transition-colors p-1" title="Close completely">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
            </button>
          </div>
        </div>
        <div className="p-5 text-sm font-medium text-red-700">
          {error}
        </div>
      </div>
    );
  }

  if (!data) return null;

  const isSafe = data.classification === 'Safe';
  const badgeColor = isSafe 
    ? 'bg-green-100 text-green-800 border-green-200' 
    : data.riskScore > 70 
      ? 'bg-red-100 text-red-800 border-red-200' 
      : 'bg-yellow-100 text-yellow-800 border-yellow-200';

  const riskLabel = isSafe ? 'Safe' : data.riskScore > 70 ? 'Critical' : 'Warning';

  return (
    <div className="fixed bottom-6 right-6 z-[9999] w-80 rounded-2xl bg-white/90 backdrop-blur-xl border border-gray-200/50 shadow-2xl overflow-hidden font-sans text-gray-800 transition-all">
      {/* Header */}
      <div className="p-4 border-b border-gray-100 flex justify-between items-center bg-gray-50/50">
        <div className="flex items-center space-x-2">
          <span className="font-bold text-lg tracking-tight text-gray-900">DigiSafe</span>
          {data.isMock && (
            <span className="text-[10px] uppercase font-bold tracking-wider bg-gray-200 text-gray-600 px-1.5 py-0.5 rounded shadow-sm">Mock</span>
          )}
        </div>
        <div className="flex items-center space-x-1">
          <button onClick={() => setIsOpen(false)} className="text-gray-400 hover:text-gray-600 transition-colors p-1" title="Minimize">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
          </button>
          <button onClick={onClose} className="text-gray-400 hover:text-red-500 transition-colors p-1" title="Close completely">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
      </div>

      {/* Body */}
      <div className="p-5 space-y-5">
        {/* Badge & Score */}
        <div className="flex items-center justify-between">
          <div className={`px-3 py-1.5 rounded-full text-xs font-bold border ${badgeColor} shadow-sm`}>
            {riskLabel} - {data.classification}
          </div>
          <div className="text-sm font-bold text-gray-700">{data.riskScore}% Risk</div>
        </div>

        {/* Progress Bar */}
        <div className="w-full bg-gray-100 rounded-full h-2.5 overflow-hidden shadow-inner">
          <div 
            className={`h-2.5 rounded-full transition-all duration-1000 ease-out ${isSafe ? 'bg-green-500' : data.riskScore > 70 ? 'bg-red-500' : 'bg-yellow-500'}`}
            style={{ width: `${data.riskScore}%` }}
          />
        </div>

        {/* Indicators */}
        {(data.indicators?.length || 0) > 0 && (
          <div className="space-y-2">
            <h4 className="text-[11px] font-bold uppercase text-gray-400 tracking-widest">Indicators</h4>
            <ul className="text-sm space-y-1.5 list-disc pl-4 text-gray-600 font-medium">
              {data.indicators?.map((indicator, idx) => (
                <li key={idx}>{indicator}</li>
              ))}
            </ul>
          </div>
        )}

        {/* Expandable Analysis */}
        {(data.flaggedPhrases?.length || 0) > 0 && (
          <div className="pt-3 border-t border-gray-100">
            <button 
              onClick={() => setExpanded(!expanded)}
              className="text-xs font-bold text-blue-600 hover:text-blue-800 flex items-center transition-colors"
            >
              <svg className={`w-3.5 h-3.5 mr-1.5 transform transition-transform ${expanded ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M9 5l7 7-7 7" /></svg>
              {expanded ? 'Hide Detailed Analysis' : 'View Detailed Analysis'}
            </button>
            
            {expanded && (
              <div className="mt-3 flex flex-wrap gap-2">
                {data.flaggedPhrases?.map((phrase, idx) => (
                  <span key={idx} className="inline-block px-2.5 py-1 bg-red-50 text-red-700 text-xs font-medium rounded-md border border-red-100/50 shadow-sm">
                    "{phrase}"
                  </span>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
