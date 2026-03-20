import { SessionService } from '../memory/session.service'
import { ConversationService } from '../conversation/conversation.service'
import { ExtractionService } from '../extraction/extraction.service'
import { MatchingService } from '../matching/matching.service'
import { NegotiationService } from '../negotiation/negotiation.service'
import { LLMService } from '../shared/llm.service'
import { AgentSession, AgentInput, AgentOutput } from '../shared/agent.types'
import { AgentStage, ExpertiseLevel } from '../shared/constants'

export class AiOrchestrator {
  private sessionService = new SessionService()
  private conversationService = new ConversationService()
  private extractionService = new ExtractionService()
  private matchingService = new MatchingService()
  private negotiationService = new NegotiationService()
  private llm = new LLMService()

  async run(input: AgentInput): Promise<AgentOutput> {
    const session = await this.sessionService.getOrCreate(input.sessionId, input.clientName)
    console.log(`\n🤖 Stage: ${session.stage} | Session: ${session.sessionId}`)

    switch (session.stage) {
      case AgentStage.UNDERSTAND: return await this.handleUnderstand(session, input.message)
      case AgentStage.ANALYZE: return await this.handleAnalyze(session, input.message)
      case AgentStage.MATCH: return await this.handleMatch(session, input.message, input.selectedFreelancerId)
      case AgentStage.OUTREACH: return await this.handleMatch(session, input.message, input.selectedFreelancerId)
      case AgentStage.NEGOTIATE: return await this.handleNegotiate(session, input.freelancerResponses || [])
      default: return { sessionId: session.sessionId, stage: session.stage, reply: 'Processing...' }
    }
  }

  private async handleUnderstand(session: AgentSession, message: string): Promise<AgentOutput> {
    const reply = await this.conversationService.handle(session, message)
    const extraction = await this.extractionService.extract(session)

    console.log(`📊 isComplete: ${extraction.isComplete} | confidence: ${extraction.confidence}`)

    const minRounds = {
      [ExpertiseLevel.BEGINNER]: 3,
      [ExpertiseLevel.INTERMEDIATE]: 2,
      [ExpertiseLevel.ADVANCED]: 1,
    }

    const expertiseLevel = session.expertiseLevel || ExpertiseLevel.BEGINNER
    const conversationRound = Math.floor(session.history.length / 2)
    const minRoundsMet = conversationRound >= minRounds[expertiseLevel]

    console.log(`💬 Round: ${conversationRound} | MinRequired: ${minRounds[expertiseLevel]} | Level: ${expertiseLevel}`)

    // ✅ LLM-based match triggering
    const shouldMatch = await this.shouldTriggerMatch(
      session,
      message,
      reply,
      extraction.isComplete,
      extraction.confidence,
      minRoundsMet
    )

    if (shouldMatch) {
      console.log(`✅ LLM decided: Triggering MATCH stage...`)
      await this.sessionService.updateStage(session.sessionId, AgentStage.MATCH)

      const updatedSession = await this.sessionService.get(session.sessionId)
      const matchSession = {
        ...updatedSession!,
        project: { ...updatedSession!.project, ...extraction.project }
      }

      const { reply: matchReply, matches } = await this.matchingService.handle(matchSession)
      console.log(`🎯 Matches found: ${matches.length}`)

      return {
        sessionId: session.sessionId,
        stage: AgentStage.MATCH,
        reply: matchReply,
        project: extraction.project,
        matches,
      }
    }

    return {
      sessionId: session.sessionId,
      stage: AgentStage.UNDERSTAND,
      reply,
      project: extraction.project,
    }
  }

  // ── LLM decides if we should trigger matching ────────────
  private async shouldTriggerMatch(
    session: AgentSession,
    userMessage: string,
    aiReply: string,
    isComplete: boolean,
    confidence: number,
    minRoundsMet: boolean
  ): Promise<boolean> {
    // Don't trigger if minimum rounds not met
    if (!minRoundsMet) return false

    // Always trigger if extraction is very confident
    if (isComplete && confidence >= 80) return true

    try {
      const prompt = `
You are deciding whether to trigger freelancer matching for a client conversation.

EXTRACTED PROJECT DATA:
${JSON.stringify(session.project, null, 2)}

LAST USER MESSAGE: "${userMessage}"
LAST AI REPLY: "${aiReply}"
IS COMPLETE: ${isComplete}
CONFIDENCE: ${confidence}%

Should we trigger freelancer matching now? Consider:
1. Do we have projectType, features, budget AND timeline?
2. Is the client ready to see freelancers?
3. Did the AI signal it has everything needed?
4. Did the user ask to find/show freelancers?

RETURN ONLY: true or false`

      const result = await this.llm.call([{ role: 'user', content: prompt }])
      const decision = result.trim().toLowerCase().includes('true')
      console.log(`🤖 LLM match decision: ${decision}`)
      return decision

    } catch (error) {
      console.error('❌ LLM match decision failed, using extraction result')
      return isComplete && confidence >= 50
    }
  }

  private async handleAnalyze(session: AgentSession, message: string): Promise<AgentOutput> {
    await this.sessionService.updateStage(session.sessionId, AgentStage.MATCH)
    const { reply, matches } = await this.matchingService.handle({
      ...session,
      stage: AgentStage.MATCH
    })
    return {
      sessionId: session.sessionId,
      stage: AgentStage.MATCH,
      reply,
      project: session.project,
      matches,
    }
  }

  private async handleMatch(
    session: AgentSession,
    message: string,
    selectedFreelancerId?: string
  ): Promise<AgentOutput> {
    const wantsToHire = /hire|want.*hire|let.*hire|go.*with|choose|select/i.test(message)

    if (wantsToHire && session.matches && session.matches.length > 0) {
      console.log(`🤝 Starting negotiation | Freelancer: ${selectedFreelancerId || 'top match'}`)
      await this.sessionService.updateStage(session.sessionId, AgentStage.NEGOTIATE)

      const updatedSession = await this.sessionService.get(session.sessionId)
      const { reply, results } = await this.negotiationService.handle(
        updatedSession!,
        [],
        selectedFreelancerId
      )

      return {
        sessionId: session.sessionId,
        stage: AgentStage.NEGOTIATE,
        reply,
        project: session.project,
        matches: session.matches,
        negotiationSummary: results,
      }
    }

    const { reply, matches } = await this.matchingService.handle(session)
    return {
      sessionId: session.sessionId,
      stage: AgentStage.MATCH,
      reply,
      project: session.project,
      matches,
    }
  }

  private async handleNegotiate(session: AgentSession, freelancerResponses: any[]): Promise<AgentOutput> {
    const { reply, results } = await this.negotiationService.handle(session, freelancerResponses)
    return {
      sessionId: session.sessionId,
      stage: AgentStage.NEGOTIATE,
      reply,
      project: session.project,
      matches: session.matches,
      negotiationSummary: results,
    }
  }
}