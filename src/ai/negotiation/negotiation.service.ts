import { LLMService } from '../shared/llm.service'
import { SessionService } from '../memory/session.service'
import {
    AgentSession,
    MatchedFreelancer,
    NegotiationResult,
    FreelancerResponse
} from '../shared/agent.types'
import { AgentStage } from '../shared/constants'
import {
    buildNegotiationOutreachPrompt,
    buildNegotiationReplyPrompt,
    buildNegotiationAnalysisPrompt
} from './negotiation.prompt'

export class NegotiationService {
    private llm = new LLMService()
    private sessionService = new SessionService()

    async handle(
        session: AgentSession,
        freelancerResponses: FreelancerResponse[] = [],
        selectedFreelancerId?: string
    ): Promise<{
        reply: string
        results: NegotiationResult[]
    }> {
        const matches = session.matches || []

        if (matches.length === 0) {
            return {
                reply: 'No freelancers to negotiate with. Please go back to matching.',
                results: []
            }
        }

        // First time — generate outreach for selected freelancer only
        if (!session.negotiationState || session.negotiationState.round === 0) {
            return await this.startOutreach(session, matches, selectedFreelancerId)
        }

        // Freelancer responses received
        if (freelancerResponses.length > 0) {
            return await this.handleResponses(session, freelancerResponses)
        }

        return {
            reply: 'Waiting for freelancer response...',
            results: session.negotiationState?.results || []
        }
    }

    // ── Contact only the selected freelancer ──────────────────
    private async startOutreach(
        session: AgentSession,
        matches: MatchedFreelancer[],
        selectedFreelancerId?: string
    ): Promise<{ reply: string; results: NegotiationResult[] }> {

        // Filter to only selected freelancer if provided
        let targetFreelancers: MatchedFreelancer[]

        if (selectedFreelancerId) {
            const selected = matches.find(m => m.id === selectedFreelancerId)
            targetFreelancers = selected ? [selected] : [matches[0]]
        } else {
            // Default: top 1 freelancer only
            targetFreelancers = [matches[0]]
        }

        const outreachMessages: string[] = []
        const results: NegotiationResult[] = []

        for (const freelancer of targetFreelancers) {
            const prompt = buildNegotiationOutreachPrompt(session, freelancer)
            const message = await this.llm.call([{ role: 'user', content: prompt }])

            outreachMessages.push(`**To ${freelancer.name}:**\n${message}`)

            results.push({
                freelancerId: freelancer.id,
                freelancerName: freelancer.name,
                status: 'PENDING',
                notes: message
            })
        }

        // Save negotiation state
        await this.sessionService.save({
            ...session,
            stage: AgentStage.NEGOTIATE,
            negotiationState: {
                responses: [],
                results,
                round: 1
            }
        })

        const freelancerName = targetFreelancers[0].name
        const reply = `I've sent an outreach message to **${freelancerName}** on your behalf!\n\n${outreachMessages[0]}\n\nI'll notify you as soon as they respond. You'll be redirected to the negotiation page now.`

        return { reply, results }
    }

    // ── Handle freelancer responses ───────────────────────────
    private async handleResponses(
        session: AgentSession,
        freelancerResponses: FreelancerResponse[]
    ): Promise<{ reply: string; results: NegotiationResult[] }> {

        const matches = session.matches || []
        const results: NegotiationResult[] = []
        const replyMessages: string[] = []

        for (const response of freelancerResponses) {
            const freelancer = matches.find(m => m.id === response.freelancerId)
            if (!freelancer) continue

            const budgetMax = session.project?.budgetMax || 0

            // Analyze reply using LLM
            const analysisPrompt = buildNegotiationAnalysisPrompt(response.replyText, budgetMax)
            const analysisRaw = await this.llm.call([{ role: 'user', content: analysisPrompt }])
            const analysis = this.parseJSON(analysisRaw, {
                status: 'PENDING' as const,
                proposedPrice: null,
                isAvailable: true,
                summary: ''
            })

            // Generate AI reply
            const replyPrompt = buildNegotiationReplyPrompt(session, freelancer, response.replyText)
            const aiReply = await this.llm.call([{ role: 'user', content: replyPrompt }])

            results.push({
                freelancerId: freelancer.id,
                freelancerName: freelancer.name,
                status: analysis.status as any,
                finalPrice: analysis.proposedPrice || undefined,
                aiReply,
                notes: analysis.summary
            })

            replyMessages.push(`**${freelancer.name}** (${analysis.status}):\n${aiReply}`)
        }

        const accepted = results.find(r => r.status === 'ACCEPTED')

        await this.sessionService.save({
            ...session,
            negotiationState: {
                responses: freelancerResponses,
                results,
                recommendedFreelancerId: accepted?.freelancerId,
                round: (session.negotiationState?.round || 1) + 1
            }
        })

        let reply = `Negotiation Update:\n\n${replyMessages.join('\n\n---\n\n')}`

        if (accepted) {
            reply += `\n\n✅ **${accepted.freelancerName} has accepted!** Ready to generate the contract.`
            await this.sessionService.save({
                ...session,
                stage: AgentStage.CONTRACT
            })
        }

        return { reply, results }
    }

    private parseJSON<T>(raw: string, fallback: T): T {
        try {
            const cleaned = raw.replace(/```json/gi, '').replace(/```/g, '').trim()
            return JSON.parse(cleaned) as T
        } catch {
            return fallback
        }
    }
}