import { LLMService } from "../shared/llm.service";

export class AssistantService {
  private llm: LLMService;

  constructor() {
    this.llm = new LLMService();
  }

  async run(message: string, history: any[]) {
    const prompt = `
You are an AI project consultant.

Your job is to:
1. Continue the conversation with the user.
2. Extract project information from the conversation.

Return STRICT JSON ONLY.

Format:
{
  "reply": "assistant reply to continue conversation",
  "project": {
    "projectType": "",
    "platform": "",
    "features": [],
    "budgetMin": null,
    "budgetMax": null,
    "timeline": ""
  }
}

Conversation history:
${JSON.stringify(history)}

User message:
${message}
`;

    const raw = await this.llm.call([{ role: "user", content: prompt }]);

    // Clean markdown if AI returns ```json
    const cleaned = raw
      .replace(/```json/g, "")
      .replace(/```/g, "")
      .trim();

    try {
      const parsed = JSON.parse(cleaned);

      return {
        reply: parsed.reply || "",
        project: parsed.project || {}
      };

    } catch (error) {

      console.error("❌ JSON parse failed");
      console.error(cleaned);

      return {
        reply: raw,
        project: {}
      };
    }
  }
}