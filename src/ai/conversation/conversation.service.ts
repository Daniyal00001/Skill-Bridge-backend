import { LLMService } from '../shared/llm.service'
import { SessionService } from '../memory/session.service'
import { buildConversationSystemPrompt } from './conversation.prompt'
import { AgentSession } from '../shared/agent.types'
import { ExpertiseLevel } from '../shared/constants'

export class ConversationService {
  private llm = new LLMService()
  private sessionService = new SessionService()

  async handle(session: AgentSession, userMessage: string): Promise<string> {

    // 1. Detect expertise level using LLM if not already set
    if (!session.expertiseLevel) {
      session.expertiseLevel = await this.detectExpertiseLevelLLM(userMessage)
      console.log(`🧠 LLM Detected expertise: ${session.expertiseLevel}`)
    }

    // 2. Count conversation rounds
    const conversationRound = Math.floor(session.history.length / 2)

    // 3. Build system prompt
    const systemPrompt = buildConversationSystemPrompt(
      session.expertiseLevel,
      session.project || {},
      session.clientName || 'Client',
      conversationRound
    )

    // 4. Build messages
    const messages = [
      { role: 'system' as const, content: systemPrompt },
      ...session.history,
      { role: 'user' as const, content: userMessage },
    ]

    // 5. Call LLM
    const reply = await this.llm.call(messages)

    // 6. Save to history
    session.history.push({ role: 'user', content: userMessage })
    session.history.push({ role: 'assistant', content: reply })
    await this.sessionService.save(session)

    return reply
  }

  // ── LLM-based expertise detection ────────────────────────
  private async detectExpertiseLevelLLM(message: string): Promise<ExpertiseLevel> {
    try {
      const prompt = `
You are analyzing a client's first message to a freelance platform AI assistant.

CLIENT MESSAGE: "${message}"

Classify the client's technical expertise level based on their message:
- BEGINNER: Vague idea, no technical terms, doesn't know what they need exactly
- INTERMEDIATE: Knows some features they want, mentions some tech or platforms
- ADVANCED: Uses technical terms, knows exact stack, mentions architecture/APIs

RETURN ONLY ONE WORD — exactly one of: BEGINNER, INTERMEDIATE, ADVANCED
No explanation, no punctuation, just the word.`

      const result = await this.llm.call([{ role: 'user', content: prompt }])
      const cleaned = result.trim().toUpperCase()

      if (cleaned.includes('ADVANCED')) return ExpertiseLevel.ADVANCED
      if (cleaned.includes('INTERMEDIATE')) return ExpertiseLevel.INTERMEDIATE
      return ExpertiseLevel.BEGINNER

    } catch (error) {
      console.error('❌ LLM expertise detection failed, using INTERMEDIATE as default')
      return ExpertiseLevel.INTERMEDIATE
    }
  }

  isProjectComplete(project: Partial<any>): boolean {
    return !!(
      project.projectType &&
      project.features?.length > 0 &&
      project.budgetMin &&
      project.budgetMax &&
      project.timeline
    )
  }
}