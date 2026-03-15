// ============================================================
// PATH: backend/src/ai/shared/constants.ts
// PURPOSE: All constants used across the AI agent modules
// ============================================================

// ── LLM Config ───────────────────────────────────────────────
export const LLM_MODEL = 'deepseek/deepseek-chat'
export const LLM_MAX_TOKENS = 2048
export const LLM_BASE_URL = 'https://openrouter.ai/api/v1/chat/completions'

// ── Agent Stages ─────────────────────────────────────────────
export enum AgentStage {
  UNDERSTAND  = 'UNDERSTAND',   // Gathering project info from client
  ANALYZE     = 'ANALYZE',      // Feasibility + project summary
  MATCH       = 'MATCH',        // Finding best freelancers from DB
  OUTREACH    = 'OUTREACH',     // Sending messages to freelancers
  NEGOTIATE   = 'NEGOTIATE',    // Handling freelancer replies
  CONTRACT    = 'CONTRACT',     // Generating final contract
  DONE        = 'DONE',         // Everything complete
}

// ── User Expertise Levels ─────────────────────────────────────
export enum ExpertiseLevel {
  BEGINNER     = 'BEGINNER',     // Vague idea, needs full guidance
  INTERMEDIATE = 'INTERMEDIATE', // Has some clarity, needs refinement
  ADVANCED     = 'ADVANCED',     // Knows exactly what they want
}

// ── Session Config ────────────────────────────────────────────
export const SESSION_TTL_SECONDS = 60 * 60 * 2   // 2 hours
export const SESSION_PREFIX = 'ai:session:'

// ── Matching Config ───────────────────────────────────────────
export const MIN_FREELANCER_RATING = 4.5
export const MAX_BUDGET_OVERAGE_PERCENT = 20      // Allow 20% over client budget
export const TOP_MATCHES_LIMIT = 10

// ── Negotiation Config ────────────────────────────────────────
export const MAX_NEGOTIATION_ROUNDS = 3

// ── Extraction: Required fields to consider project "complete" ─
export const REQUIRED_PROJECT_FIELDS = [
  'projectType',
  'features',
  'budgetMin',
  'budgetMax',
  'timeline',
]