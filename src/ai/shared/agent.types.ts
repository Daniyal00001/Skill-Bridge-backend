import { AgentStage, ExpertiseLevel } from './constants'

export interface LLMMessage {
  role: 'system' | 'user' | 'assistant'
  content: string
}

export interface AgentSession {
  sessionId: string
  clientId?: string
  clientName?: string
  stage: AgentStage
  expertiseLevel?: ExpertiseLevel
  history: LLMMessage[]
  project?: Partial<ProjectRequirements>
  matches?: MatchedFreelancer[]
  negotiationState?: NegotiationState
  contractText?: string
  createdAt: string
  updatedAt: string
}

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

export interface FreelancerProfile {
  id: string
  name: string
  location: string
  skills: string[]
  rating: number
  hourlyRate: number
  completedProjects: number
  bio: string
  availability: boolean
  specializations: string[]
}

export interface MatchedFreelancer extends FreelancerProfile {
  matchScore: number
  estimatedTotal: number
  matchReason: string
}

export interface FreelancerResponse {
  freelancerId: string
  freelancerName: string
  replyText: string
  proposedPrice?: number
  isAvailable?: boolean
}

export interface NegotiationResult {
  freelancerId: string
  freelancerName: string
  status: 'ACCEPTED' | 'PENDING' | 'DECLINED' | 'COUNTERED' | 'NO_REPLY'
  finalPrice?: number
  aiReply?: string
  notes: string
}

export interface NegotiationState {
  responses: FreelancerResponse[]
  results: NegotiationResult[]
  recommendedFreelancerId?: string
  round: number
}

export interface AgentInput {
  sessionId: string
  message: string
  clientName?: string
  freelancerResponses?: FreelancerResponse[]
  selectedFreelancerId?: string  // ← NEW
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