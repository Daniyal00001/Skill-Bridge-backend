// ============================================================
// PATH: backend/src/ai/assistant.controller.ts
// PURPOSE: Single public endpoint. Receives all messages from
//          frontend, passes to orchestrator, returns response.
// ============================================================

import { Request, Response } from 'express'
import { AiOrchestrator } from './orchestrator/ai.orchestrator'

const orchestrator = new AiOrchestrator()

export async function handleAssistantMessage(req: Request, res: Response) {
  try {
    const { message, sessionId, clientName, freelancerResponses } = req.body

    // ── Validate ────────────────────────────────────────────
    if (!message || typeof message !== 'string') {
      return res.status(400).json({ error: 'message is required and must be a string' })
    }

    // ── Run orchestrator ────────────────────────────────────
    const result = await orchestrator.run({
      sessionId,
      message,
      clientName: clientName || 'Client',
      freelancerResponses: freelancerResponses || [],
    })

    // ── Return response ─────────────────────────────────────
    return res.json({
      success: true,
      sessionId: result.sessionId,
      stage: result.stage,
      reply: result.reply,
      project: result.project || null,
      matches: result.matches || null,
      negotiationSummary: result.negotiationSummary || null,
      contractText: result.contractText || null,
    })

  } catch (error: any) {
    console.error('❌ Controller error:', error.message)
    return res.status(500).json({ error: error.message })
  }
}