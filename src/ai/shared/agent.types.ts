// ============================================================
// PATH: backend/src/ai/shared/agent.types.ts
// PURPOSE: All TypeScript interfaces and types used across
//          every AI module in the agent pipeline
// ============================================================

import { AgentStage, ExpertiseLevel } from './constants'

// ── LLM ──────────────────────────────────────────────────────
export interface LLMMessage {
  role: 'system' | 'user' | 'assistant'
  content: string
}

// ── Session / Memory ─────────────────────────────────────────
export interface AgentSession {
  sessionId: string
  clientId?: string                        // logged-in user ID (optional)
  clientName?: string
  stage: AgentStage
  expertiseLevel?: ExpertiseLevel
  history: LLMMessage[]                   // full conversation so far
  project?: Partial<ProjectRequirements>  // extracted project data
  matches?: MatchedFreelancer[]           // matched freelancers
  negotiationState?: NegotiationState
  contractText?: string
  createdAt: string
  updatedAt: string
}

// ── Project Requirements ─────────────────────────────────────
export interface ProjectRequirements {
  projectType: string | null
  platform: string | null
  features: string[]
  budgetMin: number | null
  budgetMax: number | null
  timeline: string | null
  techPreferences: string[]
  expertiseNeeded: 'entry' | 'intermediate' | 'senior' | null
  additionalNotes: string | null
}

// ── Freelancer ───────────────────────────────────────────────
export interface FreelancerProfile {
  id: string
  name: string
  location: string
  skills: string[]
  rating: number               // 0.0 – 5.0
  hourlyRate: number           // USD per hour
  completedProjects: number
  bio: string
  availability: boolean
  specializations: string[]
}

export interface MatchedFreelancer extends FreelancerProfile {
  matchScore: number           // 0–100
  estimatedTotal: number       // USD (hourly * estimated hours)
  matchReason: string          // why this freelancer was selected
}

// ── Negotiation ──────────────────────────────────────────────
export interface FreelancerResponse {
  freelancerId: string
  freelancerName: string
  replyText: string            // raw text of their reply
  proposedPrice?: number
  isAvailable?: boolean
}

export interface NegotiationResult {
  freelancerId: string
  freelancerName: string
  status: 'ACCEPTED' | 'PENDING' | 'DECLINED' | 'COUNTERED' | 'NO_REPLY'
  finalPrice?: number
  aiReply?: string             // what the AI sent back to freelancer
  notes: string
}

export interface NegotiationState {
  responses: FreelancerResponse[]
  results: NegotiationResult[]
  recommendedFreelancerId?: string
  round: number
}

// ── Orchestrator I/O ─────────────────────────────────────────
export interface AgentInput {
  sessionId: string
  message: string
  clientName?: string
  // Injected at specific stages:
  freelancerResponses?: FreelancerResponse[]
}

export interface AgentOutput {
  sessionId: string
  reply: string
  stage: AgentStage
  project?: Partial<ProjectRequirements>
  matches?: MatchedFreelancer[]
  negotiationSummary?: NegotiationResult[]
  contractText?: string
}