import { LLMService, LLMMessage } from '../shared/llm.service'
import { SessionService } from '../memory/session.service'
import { PrismaClient } from '@prisma/client'
import { buildExtractionPrompt, buildExtractionCheckPrompt } from './extraction.prompt'
import { AgentSession, ProjectRequirements } from '../shared/agent.types'

export interface ExtractionResult {
  project: Partial<ProjectRequirements>
  isComplete: boolean
  missingFields: string[]
  confidence: number
}

const prisma = new PrismaClient()

export class ExtractionService {
  private llm = new LLMService()
  private sessionService = new SessionService()

  async extract(session: AgentSession): Promise<ExtractionResult> {
    // ✅ Fetch real skills from DB
    const dbSkills = await prisma.skill.findMany({
      select: { name: true, category: true }
    })
    const skillNames = dbSkills.map(s => s.name)

    const project = await this.extractProjectData(session, skillNames)
    session.project = { ...session.project, ...project }
    await this.sessionService.save(session)

    const { isComplete, missingFields, confidence } = await this.checkCompleteness(session)

    console.log(`📋 isComplete: ${isComplete} | confidence: ${confidence}%`)
    console.log(`📋 Extracted:`, JSON.stringify(project, null, 2))

    return { project, isComplete, missingFields, confidence }
  }

  private async extractProjectData(
    session: AgentSession,
    availableSkills: string[]
  ): Promise<Partial<ProjectRequirements>> {
    const prompt = buildExtractionPrompt(session, availableSkills)
    const messages: LLMMessage[] = [{ role: 'user', content: prompt }]
    const raw = await this.llm.call(messages)
    return this.parseJSON<Partial<ProjectRequirements>>(raw, {
      projectType: null,
      platform: null,
      features: [],
      budgetMin: null,
      budgetMax: null,
      timeline: null,
      techPreferences: [],
      expertiseNeeded: null,
      additionalNotes: null,
    })
  }

  private async checkCompleteness(session: AgentSession): Promise<{
    isComplete: boolean
    missingFields: string[]
    confidence: number
  }> {
    const prompt = buildExtractionCheckPrompt(session)
    const messages: LLMMessage[] = [{ role: 'user', content: prompt }]
    const raw = await this.llm.call(messages)
    return this.parseJSON(raw, {
      isComplete: false,
      missingFields: [],
      confidence: 0,
    })
  }

  private parseJSON<T>(raw: string, fallback: T): T {
    try {
      const cleaned = raw.replace(/```json/gi, '').replace(/```/g, '').trim()
      return JSON.parse(cleaned) as T
    } catch (err) {
      console.error('❌ ExtractionService JSON parse failed:', raw)
      return fallback
    }
  }
}