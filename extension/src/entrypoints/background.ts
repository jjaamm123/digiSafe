import { defineBackground } from 'wxt/sandbox';
import { supabase } from '@/utils/supabase';
import { triageMessage } from '@/utils/localClassifier';
import { runLocalExplainability, LocalAnalysisResult } from '@/utils/localExplainer';
import { buildBlindDigest } from '@/utils/featureExtractor';

export async function handleScanOrchestration(payload: {
  text: string;
  sender?: string;
  source: 'gmail' | 'whatsapp' | 'linkedin';
  metadata?: Record<string, any>;
}) {
  const senderStr = payload.sender || '';

  const triage = await triageMessage(payload.text, payload.source);
  const localAnalysis: LocalAnalysisResult = runLocalExplainability(
    payload.text,
    triage.confidence,
    triage.isSuspicious,
    triage.label,
    senderStr,
    payload.source
  );

  if (localAnalysis.classification === 'Safe') {
    const safePayload = {
      ...localAnalysis,
      sender: localAnalysis.sender || senderStr,
      engine: 'edge_verified_safe',
      isMock: false,
      isLocalTriage: false,
    };

    relayAnonymizedTelemetry(payload, safePayload).catch((telemetryErr) => {
      console.warn('[DigiSafe] Telemetry relay failed (non-blocking):', telemetryErr);
    });

    return safePayload;
  }

  const blindDigest = buildBlindDigest(
    payload.text,
    payload.source,
    senderStr,
    localAnalysis.riskScore,
    localAnalysis.classification,
    localAnalysis.flaggedPhrases,
    localAnalysis.linkForensics || []
  );

  let finalResult = {
    ...localAnalysis,
    sender: localAnalysis.sender || senderStr,
    engine: 'local_heuristic_fallback',
    isMock: false,
    isLocalTriage: false,
  };

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6000); // 6s timeout

    const res = await fetch('http://localhost:3000/api/synthesize-threat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(blindDigest),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      if (data.explanation) {
        finalResult = {
          ...localAnalysis,
          sender: localAnalysis.sender || senderStr,
          explanation: data.explanation,
          actionableGuidance: data.actionableGuidance || localAnalysis.actionableGuidance,
          engine: 'gemini_zero_knowledge',
          isMock: false,
          isLocalTriage: false,
        };
      }
    } else {
      console.warn(`[DigiSafe] Backend returned ${res.status}. Falling back to local heuristic synthesis.`);
    }
  } catch (err) {
    console.warn('[DigiSafe] Gemini synthesis unavailable. Serving edge heuristic synthesis.');
  }

  relayAnonymizedTelemetry(payload, finalResult).catch((telemetryErr) => {
    console.warn('[DigiSafe] Telemetry relay failed (non-blocking):', telemetryErr);
  });

  return finalResult;
}

async function relayAnonymizedTelemetry(
  payload: { text: string; sender?: string; source: string },
  localResult: LocalAnalysisResult
) {
  try {
    const { data: { session } } = await supabase.auth.getSession();
    const token = session?.access_token;

    if (!token) {
      console.log('[DigiSafe] No active session — skipping telemetry relay.');
      return;
    }

    const safeTelemetry = {
      source: payload.source,
      threat_category: localResult.classification,
      confidence_score: localResult.riskScore,
      raw_text_length: payload.text.length,
      indicators: localResult.indicators,
    };

    const API_URL = 'http://localhost:3000/api/scan';

    await fetch(API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify(safeTelemetry),
    });

    console.log('[DigiSafe] Anonymized telemetry relayed successfully.');
  } catch (err) {
    console.warn('[DigiSafe] Telemetry relay error (swallowed):', err);
  }
}

export default defineBackground(() => {
  console.log('DigiSafe Background Worker initialized (v2.0.0 — Zero-Knowledge Edge Pipeline).');

  browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'SCAN_REQUEST') {
      handleScanOrchestration(message.payload)
        .then((data) => sendResponse({ success: true, data }))
        .catch((err) => {
          console.error('[DigiSafe Background Worker] Edge Scan Failure:', err);
          sendResponse({
            success: false,
            error: `${err.message || 'Local scan failed'}. Please refresh and retry.`
          });
        });
      return true;
    }
  });
});
