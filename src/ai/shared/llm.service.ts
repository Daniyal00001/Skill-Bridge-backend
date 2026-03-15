import axios from "axios";

export interface LLMMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export class LLMService {

  async call(messages: LLMMessage[] | string) {
    try {
      // Support both string (legacy) and messages array
      const formattedMessages = typeof messages === 'string'
        ? [{ role: 'user' as const, content: messages }]
        : messages;

      const response = await axios.post(
        "https://openrouter.ai/api/v1/chat/completions",
        {
          model: "deepseek/deepseek-chat",
          messages: formattedMessages
        },
        {
          headers: {
            Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}`,
            "Content-Type": "application/json"
          }
        }
      );

      return response.data.choices[0].message.content;

    } catch (error: any) {
      console.error("LLM Error:", error.response?.data || error.message);
      throw new Error("LLM request failed");
    }
  }
}

export default LLMService;