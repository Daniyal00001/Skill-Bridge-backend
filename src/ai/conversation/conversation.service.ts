// ============================================================
// PATH: backend/src/ai/conversation/conversation.service.ts
// PURPOSE: Drives the UNDERSTAND stage. Detects user expertise
//          level, builds prompt, calls LLM, returns reply.
// ============================================================

import { LLMService } from '../shared/llm.service'
import { SessionService } from '../memory/session.service'
import { buildConversationSystemPrompt } from './conversation.prompt'
import { AgentSession } from '../shared/agent.types'
import { ExpertiseLevel } from '../shared/constants'

export class ConversationService {
  private llm = new LLMService()
  private sessionService = new SessionService()

  // ── Main entry: handle one user message in UNDERSTAND stage ──
  async handle(session: AgentSession, userMessage: string): Promise<string> {

    // 1. Detect expertise level if not already set
    if (!session.expertiseLevel) {
      session.expertiseLevel = this.detectExpertiseLevel(userMessage)
      console.log(`🧠 Detected expertise level: ${session.expertiseLevel}`)
    }

    // 2. Build system prompt based on level + missing fields
    const systemPrompt = buildConversationSystemPrompt(
      session.expertiseLevel,
      session.project || {},
      session.clientName || 'Client'
    )

    // 3. Build messages array: system + full history + new user message
    const messages = [
      { role: 'system' as const, content: systemPrompt },
      ...session.history,
      { role: 'user' as const, content: userMessage },
    ]

    // 4. Call LLM
    const reply = await this.llm.call(messages)

    // 5. Save user message + assistant reply to session history
    session.history.push({ role: 'user', content: userMessage })
    session.history.push({ role: 'assistant', content: reply })
    await this.sessionService.save(session)

    return reply
  }

  // ── Detect expertise level from first message ─────────────
  detectExpertiseLevel(message: string): ExpertiseLevel {
    const lower = message.toLowerCase()

    // Advanced signals: technical stack terms, architecture, SaaS, etc.
    const advancedKeywords = [
      'rest api', 'graphql', 'microservice', 'websocket', 'docker',
      'kubernetes', 'multi-tenant', 'saas', 'oauth', 'jwt', 'redis',
      'postgresql', 'mongodb', 'role-based', 'rbac', 'typescript',
      'next.js', 'nestjs', 'fastapi', 'django', 'spring boot',
      'ci/cd', 'deployment', 'aws', 'gcp', 'azure', 'fedex api',
      'stripe api', 'webhook', 'sdk', 'integration', 'architecture'
    ]

    // Intermediate signals: knows features, budget, some tech
    const intermediateKeywords = [
      'dashboard', 'authentication', 'login', 'payment', 'stripe',
      'notification', 'mobile app', 'web app', 'flutter', 'react',
      'node', 'database', 'admin panel', 'user management',
      'budget', 'timeline', 'deadline', 'marketplace', 'ecommerce',
      'api', 'backend', 'frontend', 'fullstack'
    ]

    const advancedScore = advancedKeywords.filter(k => lower.includes(k)).length
    const intermediateScore = intermediateKeywords.filter(k => lower.includes(k)).length

    if (advancedScore >= 2) return ExpertiseLevel.ADVANCED
    if (intermediateScore >= 2 || advancedScore === 1) return ExpertiseLevel.INTERMEDIATE
    return ExpertiseLevel.BEGINNER
  }

  // ── Check if we have enough info to move to ANALYZE stage ──
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