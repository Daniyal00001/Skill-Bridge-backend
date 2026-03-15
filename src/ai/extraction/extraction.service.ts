// ============================================================
// PATH: backend/src/ai/extraction/extraction.service.ts
// PURPOSE: Calls LLM to extract structured project data from
//          conversation history and saves it to session
// ============================================================

import { LLMService, LLMMessage } from '../shared/llm.service'
import { SessionService } from '../memory/session.service'
import { buildExtractionPrompt, buildExtractionCheckPrompt } from './extraction.prompt'
import { AgentSession, ProjectRequirements } from '../shared/agent.types'

export interface ExtractionResult {
  project: Partial<ProjectRequirements>
  isComplete: boolean
  missingFields: string[]
  confidence: number
}

export class ExtractionService {
  private llm = new LLMService()
  private sessionService = new SessionService()

  // ── Main: extract + check completeness ───────────────────
  async extract(session: AgentSession): Promise<ExtractionResult> {

    // 1. Extract structured project data from conversation
    const project = await this.extractProjectData(session)

    // 2. Update session with extracted data
    session.project = { ...session.project, ...project }
    await this.sessionService.save(session)

    // 3. Check if we have enough to proceed
    const { isComplete, missingFields, confidence } = await this.checkCompleteness(session)

    console.log(`📋 Extraction complete | isComplete: ${isComplete} | confidence: ${confidence}%`)
    console.log(`📋 Extracted:`, JSON.stringify(project, null, 2))

    return {
      project,
      isComplete,
      missingFields,
      confidence,
    }
  }

  // ── Extract project data from conversation ────────────────
  private async extractProjectData(
    session: AgentSession
  ): Promise<Partial<ProjectRequirements>> {
    const prompt = buildExtractionPrompt(session)

    const messages: LLMMessage[] = [
      { role: 'user', content: prompt },
    ]

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

  // ── Check if project data is complete ────────────────────
  private async checkCompleteness(session: AgentSession): Promise<{
    isComplete: boolean
    missingFields: string[]
    confidence: number
  }> {
    const prompt = buildExtractionCheckPrompt(session)

    const messages: LLMMessage[] = [
      { role: 'user', content: prompt },
    ]

    const raw = await this.llm.call(messages)
    return this.parseJSON(raw, {
      isComplete: false,
      missingFields: [],
      confidence: 0,
    })
  }

  // ── Safe JSON parser ──────────────────────────────────────
  private parseJSON<T>(raw: string, fallback: T): T {
    try {
      const cleaned = raw
        .replace(/```json/gi, '')
        .replace(/```/g, '')
        .trim()

      return JSON.parse(cleaned) as T
    } catch (err) {
      console.error('❌ ExtractionService JSON parse failed:', raw)
      return fallback
    }
  }
}