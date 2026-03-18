import axios from "axios";

export interface LLMMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

interface GroqResponse {
  choices: {
    message: {
      content: string;
    };
  }[];
}

export class LLMService {

  async call(messages: LLMMessage[] | string) {
    const maxRetries = 3
    let lastError: any

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const formattedMessages = typeof messages === 'string'
          ? [{ role: 'user' as const, content: messages }]
          : messages

        const response = await axios.post<GroqResponse>(
          "https://api.groq.com/openai/v1/chat/completions",
          {
            model: "llama-3.3-70b-versatile",
            max_tokens: 500,
            messages: formattedMessages
          },
          {
            headers: {
              Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
              "Content-Type": "application/json"
            }
          }
        )

        return response.data.choices[0].message.content

      } catch (error: any) {
        lastError = error
        const code = error.response?.data?.error?.code
        const status = error.response?.status

        if (code === 429 || status === 429) {
          console.log(`⏳ Rate limited — retrying in ${attempt * 2}s (attempt ${attempt}/${maxRetries})`)
          await new Promise(resolve => setTimeout(resolve, attempt * 2000))
          continue
        }

        console.error("LLM Error:", error.response?.data || error.message)
        throw new Error("LLM request failed")
      }
    }

    console.error("LLM Error:", lastError?.response?.data || lastError?.message)
    throw new Error("LLM request failed after retries")
  }
}

export default LLMService;
