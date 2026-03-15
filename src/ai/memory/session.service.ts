// ============================================================
// PATH: backend/src/ai/memory/session.service.ts
// PURPOSE: Stores and retrieves agent session from Redis
//          Each session holds stage, history, project data
// ============================================================

import redis from '../../config/redis'
import { AgentSession } from '../shared/agent.types'
import { AgentStage, SESSION_PREFIX, SESSION_TTL_SECONDS } from '../shared/constants'
import { v4 as uuidv4 } from 'uuid'

export class SessionService {

  // ── Build Redis key from sessionId ───────────────────────
  private key(sessionId: string): string {
    return `${SESSION_PREFIX}${sessionId}`
  }

  // ── Create a brand new session ───────────────────────────
  async create(clientName?: string, clientId?: string): Promise<AgentSession> {
    const session: AgentSession = {
      sessionId: uuidv4(),
      clientId,
      clientName: clientName || 'Client',
      stage: AgentStage.UNDERSTAND,
      history: [],
      project: {},
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }

    await this.save(session)
    return session
  }

  // ── Get existing session by ID ───────────────────────────
  async get(sessionId: string): Promise<AgentSession | null> {
    try {
      const raw = await redis.get(this.key(sessionId))
      if (!raw) return null
      return JSON.parse(raw) as AgentSession
    } catch (err) {
      console.error('❌ SessionService.get error:', err)
      return null
    }
  }

  // ── Save / update session ────────────────────────────────
  async save(session: AgentSession): Promise<void> {
    try {
      session.updatedAt = new Date().toISOString()
      await redis.set(
        this.key(session.sessionId),
        JSON.stringify(session),
        { EX: SESSION_TTL_SECONDS }
      )
    } catch (err) {
      console.error('❌ SessionService.save error:', err)
      throw err
    }
  }

  // ── Update stage ─────────────────────────────────────────
  async updateStage(sessionId: string, stage: AgentStage): Promise<void> {
    const session = await this.get(sessionId)
    if (!session) throw new Error(`Session not found: ${sessionId}`)
    session.stage = stage
    await this.save(session)
  }

  // ── Append message to history ────────────────────────────
  async appendMessage(
    sessionId: string,
    role: 'user' | 'assistant',
    content: string
  ): Promise<void> {
    const session = await this.get(sessionId)
    if (!session) throw new Error(`Session not found: ${sessionId}`)
    session.history.push({ role, content })
    await this.save(session)
  }

  // ── Update extracted project data ────────────────────────
  async updateProject(sessionId: string, project: object): Promise<void> {
    const session = await this.get(sessionId)
    if (!session) throw new Error(`Session not found: ${sessionId}`)
    session.project = { ...session.project, ...project }
    await this.save(session)
  }

  // ── Delete session (cleanup) ─────────────────────────────
  async delete(sessionId: string): Promise<void> {
    await redis.del(this.key(sessionId))
  }

  // ── Get or create session ────────────────────────────────
  async getOrCreate(sessionId?: string, clientName?: string, clientId?: string): Promise<AgentSession> {
    if (sessionId) {
      const existing = await this.get(sessionId)
      if (existing) return existing
    }
    return this.create(clientName, clientId)
  }
}