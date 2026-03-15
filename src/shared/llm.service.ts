// ============================================================
// PATH: backend/src/ai/shared/llm.service.ts
// PURPOSE: Real OpenRouter API call using deepseek/deepseek-chat
// ============================================================

import axios from 'axios'

export interface LLMMessage {
  role: 'system' | 'user' | 'assistant'
  content: string
}

export class LLMService {
  private readonly apiKey = process.env.OPENROUTER_API_KEY!
  private readonly model = 'deepseek/deepseek-chat'
  private readonly baseURL = 'https://openrouter.ai/api/v1/chat/completions'

  async call(messages: LLMMessage[]): Promise<string> {
    try {
      const response = await axios.post(
        this.baseURL,
        {
          model: this.model,
          max_tokens: 2048,
          messages,
        },
        {
          headers: {
            'Authorization': `Bearer ${this.apiKey}`,
            'Content-Type': 'application/json',
            'HTTP-Referer': process.env.FRONTEND_URL || 'http://localhost:8080',
            'X-Title': 'SkillBridge FreelanceAI',
          },
        }
      )

      const content = response.data?.choices?.[0]?.message?.content

      if (!content) {
        throw new Error('No content returned from OpenRouter')
      }

      return content as string

    } catch (error: any) {
      const msg = error?.response?.data?.error?.message || error.message
      console.error('❌ LLMService error:', msg)
      throw new Error(`LLM call failed: ${msg}`)
    }
  }
}