import { SessionService } from '../memory/session.service'
import { ConversationService } from '../conversation/conversation.service'
import { ExtractionService } from '../extraction/extraction.service'
import { MatchingService } from '../matching/matching.service'
import { NegotiationService } from '../negotiation/negotiation.service'
import { AgentSession, AgentInput, AgentOutput } from '../shared/agent.types'
import { AgentStage, ExpertiseLevel } from '../shared/constants'

export class AiOrchestrator {
  private sessionService = new SessionService()
  private conversationService = new ConversationService()
  private extractionService = new ExtractionService()
  private matchingService = new MatchingService()
  private negotiationService = new NegotiationService()

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

    const aiSignalsComplete = /perfect.*everything|have everything|find.*best freelancer|matching you now|let me find|finding.*freelancer/i.test(reply)
    const userWantsMatch = /find|freelancer|match|proceed|yes|show|search|hire/i.test(message)
    const hasBasicInfo = !!(
      extraction.project.projectType &&
      extraction.project.features?.length &&
      extraction.project.budgetMin
    )

    const shouldMatch =
      (extraction.isComplete && extraction.confidence >= 50 && minRoundsMet) ||
      (aiSignalsComplete && hasBasicInfo && minRoundsMet) ||
      (userWantsMatch && hasBasicInfo && minRoundsMet)

    if (shouldMatch) {
      console.log(`✅ Triggering MATCH stage...`)
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
        selectedFreelancerId  // ← pass selected freelancer
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