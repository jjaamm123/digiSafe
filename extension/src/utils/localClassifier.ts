import { pipeline, env } from '@huggingface/transformers';

env.allowLocalModels = false;
env.useBrowserCache = true;
env.backends.onnx.wasm.numThreads = 1;

export interface TriageResult {
  isSuspicious: boolean;
  confidence: number;
  label: string;
  source: 'local_edge';
}

class LocalClassifier {
  private static instance: any = null;
  private static isInitializing = false;

  private static async getPipeline() {
    if (!this.instance && !this.isInitializing) {
      this.isInitializing = true;
      try {
        this.instance = await pipeline(
          'text-classification',
          'onnx-community/phishing-email-detection-distilbert_v2.4.1-ONNX',
          { device: 'wasm', dtype: 'q8' }
        );
        console.log('[DigiSafe Edge AI] ONNX pipeline loaded successfully.');
      } catch (error) {
        console.warn('[DigiSafe Edge AI] Failed to load ONNX pipeline:', error);
        this.instance = null;
      } finally {
        this.isInitializing = false;
      }
    }
    return this.instance;
  }

  public static async triage(
    text: string,
    source: 'gmail' | 'whatsapp' | 'linkedin'
  ): Promise<TriageResult> {
    try {
      const classifier = await this.getPipeline();
      if (!classifier) {
        return { isSuspicious: true, confidence: 0, label: 'FALLBACK', source: 'local_edge' };
      }

      const truncatedText = text.slice(0, 2000);
      const output = await classifier(truncatedText);
      const topResult = output[0];

      const isSafe = topResult.label === 'LABEL_0' && topResult.score >= 0.70;

      return {
        isSuspicious: !isSafe,
        confidence: topResult.score,
        label: topResult.label,
        source: 'local_edge',
      };
    } catch (err) {
      console.error('[DigiSafe Edge AI] Classification error:', err);
      return { isSuspicious: true, confidence: 0, label: 'ERROR', source: 'local_edge' };
    }
  }
}

export const triageMessage = LocalClassifier.triage.bind(LocalClassifier);
