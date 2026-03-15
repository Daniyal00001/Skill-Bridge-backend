// ============================================================
// PATH: backend/src/ai/orchestrator/ai.orchestrator.ts
// PURPOSE: The brain of the agent. Controls flow between all
//          stages: UNDERSTAND → ANALYZE → MATCH → NEGOTIATE → CONTRACT
// ============================================================

import { SessionService } from '../memory/session.service'
import { ConversationService } from '../conversation/conversation.service'
import { ExtractionService } from '../extraction/extraction.service'
import { AgentSession, AgentInput, AgentOutput } from '../shared/agent.types'
import { AgentStage } from '../shared/constants'

export class AiOrchestrator {
  private sessionService    = new SessionService()
  private conversationService = new ConversationService()
  private extractionService = new ExtractionService()

  // ── Main entry point ─────────────────────────────────────
  async run(input: AgentInput): Promise<AgentOutput> {
    // 1. Get or create session
    const session = await this.sessionService.getOrCreate(
      input.sessionId,
      input.clientName
    )

    console.log(`\n🤖 Orchestrator | Stage: ${session.stage} | Session: ${session.sessionId}`)

    // 2. Route to correct stage handler
    switch (session.stage) {
      case AgentStage.UNDERSTAND:
        return await this.handleUnderstand(session, input.message)

      case AgentStage.ANALYZE:
        return await this.handleAnalyze(session, input.message)

      default:
        return {
          sessionId: session.sessionId,
          stage: session.stage,
          reply: 'I am processing your request. Please wait...',
        }
    }
  }

  // ── STAGE 1: UNDERSTAND ───────────────────────────────────
  // Collect project info through conversation
  private async handleUnderstand(
    session: AgentSession,
    message: string
  ): Promise<AgentOutput> {

    // 1. Get conversational reply from AI
    const reply = await this.conversationService.handle(session, message)

    // 2. After every message, try to extract project data silently
    const extraction = await this.extractionService.extract(session)

    // 3. If project is complete, move to ANALYZE stage
    if (extraction.isComplete && extraction.confidence >= 70) {
      console.log(`✅ Project complete! Moving to ANALYZE stage...`)
      await this.sessionService.updateStage(session.sessionId, AgentStage.ANALYZE)

      return {
        sessionId: session.sessionId,
        stage: AgentStage.ANALYZE,
        reply,
        project: extraction.project,
      }
    }

    // 4. Still collecting info
    return {
      sessionId: session.sessionId,
      stage: AgentStage.UNDERSTAND,
      reply,
      project: extraction.project,
    }
  }

  // ── STAGE 2: ANALYZE ──────────────────────────────────────
  // Generate project summary + feasibility analysis
  private async handleAnalyze(
    session: AgentSession,
    message: string
  ): Promise<AgentOutput> {

    // Continue conversation while in analyze stage
    const reply = await this.conversationService.handle(session, message)

    // Move to MATCH stage after analysis confirmed
    await this.sessionService.updateStage(session.sessionId, AgentStage.MATCH)

    return {
      sessionId: session.sessionId,
      stage: AgentStage.MATCH,
      reply,
      project: session.project,
    }
  }
}