import axios, { AxiosError } from 'axios';

// Fallback models tried in order when the primary fails
const FALLBACK_MODELS = ['llama-3.1-8b-instant', 'gemma2-9b-it'];
const RETRYABLE_STATUS_CODES = [429, 500, 502, 503, 504];

export class LLMService {
  private apiKey: string;
  private baseUrl: string;
  private primaryModel: string;
  private maxRetries: number;

  constructor() {
    this.apiKey = process.env.GROQ_API_KEY || '';
    this.baseUrl = 'https://api.groq.com/openai/v1/chat/completions';
    this.primaryModel = 'llama-3.3-70b-versatile';
    this.maxRetries = 4;
  }

  /**
   * Sleep helper with exponential backoff + jitter
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  private backoffMs(attempt: number): number {
    return Math.min(2 ** attempt * 1000 + Math.random() * 1000, 30_000);
  }

  /**
   * Core request with retries and transient-error handling
   */
  private async request(
    model: string,
    messages: any[],
    maxTokens: number,
    maxRetries: number
  ): Promise<string> {
    let lastError: Error | null = null;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const response = await axios.post(
          this.baseUrl,
          { model, messages, max_tokens: maxTokens },
          {
            headers: {
              Authorization: `Bearer ${this.apiKey}`,
              'Content-Type': 'application/json',
            },
            timeout: 60_000,
          }
        );

        return response.data.choices[0].message.content;
      } catch (error: any) {
        lastError = error;
        const status = (error as AxiosError)?.response?.status;

        // Retryable transient errors
        if (status && RETRYABLE_STATUS_CODES.includes(status)) {
          // Respect Retry-After header if provided
          const retryAfter = (error as AxiosError)?.response?.headers?.[
            'retry-after'
          ];
          const waitMs = retryAfter
            ? parseFloat(retryAfter) * 1000
            : this.backoffMs(attempt);

          console.warn(
            `⏳ [${model}] HTTP ${status} — retrying in ${Math.round(waitMs)}ms ` +
              `(attempt ${attempt}/${maxRetries})`
          );
          await this.sleep(waitMs);
          continue;
        }

        // Timeout / network errors are also retryable
        if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
          console.warn(
            `⏰ [${model}] Timeout (attempt ${attempt}/${maxRetries})`
          );
          await this.sleep(this.backoffMs(attempt));
          continue;
        }

        // Non-retryable error — rethrow immediately
        console.error(
          `❌ [${model}] Non-retryable error: ${error.message}`
        );
        throw error;
      }
    }

    throw lastError || new Error(`LLM request to ${model} failed after ${maxRetries} retries`);
  }

  /**
   * Main entry point — tries primary model, then fallback chain
   */
  async call(messages: any[]): Promise<string> {
    // 1. Try primary model
    try {
      return await this.request(
        this.primaryModel,
        messages,
        1000,
        this.maxRetries
      );
    } catch (primaryErr: any) {
      console.warn(
        `⚠️ Primary model [${this.primaryModel}] failed: ${primaryErr.message}. Trying fallbacks...`
      );
    }

    // 2. Fallback chain
    for (const fallbackModel of FALLBACK_MODELS) {
      try {
        console.log(`🔄 Attempting fallback: ${fallbackModel}`);
        const result = await this.request(fallbackModel, messages, 1024, 2);
        console.log(`✅ Fallback [${fallbackModel}] succeeded`);
        return result;
      } catch (fbErr: any) {
        console.error(
          `❌ Fallback [${fallbackModel}] also failed: ${fbErr.message}`
        );
      }
    }

    throw new Error(
      `All LLM models failed (primary: ${this.primaryModel}, fallbacks: ${FALLBACK_MODELS.join(', ')})`
    );
  }
}
