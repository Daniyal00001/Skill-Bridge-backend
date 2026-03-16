/**
 * browse.scoring.ts
 * location: backend/src/modules/browse/browse.scoring.ts
 * ─────────────────────────────────────────────────────────────────
 * WHY HERE: Pure scoring logic with no DB calls or side effects.
 * Keeping scoring separate from service means:
 *   - Easy to unit test (just pass objects, check output)
 *   - Easy to tune weights without touching service code
 *   - Can be replaced with ML model later — just swap this file
 *
 * FORMULA:
 *   finalScore = Σ (dimensionScore × weight) × (1 + personalBoost)
 *
 * Each dimension produces a 0–100 score.
 * Weights are defined in browse.types.ts SCORING_WEIGHTS.
 * ─────────────────────────────────────────────────────────────────
 */

import {
  FreelancerSnapshot,
  RawProject,
  SCORING_WEIGHTS,
} from './browse.types'

// ── Returned by scoreProject ────────────────────────────────────
export interface ProjectScore {
  score: number            // 0–100 final weighted score
  matchPercentage: number  // human-readable match % shown on card
  isExploration: boolean   // always false here; set later by injection
  scoreBreakdown: {
    skillMatch: number
    freshness: number
    competition: number
    budgetFit: number
    clientTrust: number
    freelancerSuccess: number
    activity: number
    personalBoost: number
  }
}

// ── MAIN EXPORT ─────────────────────────────────────────────────
export function scoreProject(
  project: RawProject,
  freelancer: FreelancerSnapshot
): ProjectScore {
  // ── 1. Skill Match (0–100) ──────────────────────────────────
  // % of project's required skills that the freelancer has.
  const projectSkillNames = (project.skills ?? []).map((s) =>
    s.skill.name.toLowerCase()
  )
  const freelancerSkillNames = (freelancer.skillNames ?? []).map((s) =>
    s.toLowerCase()
  )

  let skillMatch = 0
  if (projectSkillNames.length > 0) {
    const matched = projectSkillNames.filter((s) =>
      freelancerSkillNames.includes(s)
    ).length
    skillMatch = Math.round((matched / projectSkillNames.length) * 100)
  }

  // ── 2. Freshness (0–100) ────────────────────────────────────
  // Projects <1 hour old → 100. Decay to 0 over 30 days.
  const ageMs = Date.now() - new Date(project.createdAt).getTime()
  const ageDays = ageMs / 86_400_000
  const freshness = Math.max(0, Math.round(100 - (ageDays / 30) * 100))

  // ── 3. Competition (0–100) ──────────────────────────────────
  // Fewer proposals = higher score (inverted + capped at 50 proposals)
  const MAX_PROPOSALS = 50
  const competition = Math.max(
    0,
    Math.round(((MAX_PROPOSALS - Math.min(project.proposalCount, MAX_PROPOSALS)) / MAX_PROPOSALS) * 100)
  )

  // ── 4. Budget Fit (0–100) ──────────────────────────────────
  // How well project budget aligns with freelancer's preferred range.
  let budgetFit = 50 // neutral default
  if (
    freelancer.preferredBudgetMin != null &&
    freelancer.preferredBudgetMax != null
  ) {
    const mid = (freelancer.preferredBudgetMin + freelancer.preferredBudgetMax) / 2
    const range = freelancer.preferredBudgetMax - freelancer.preferredBudgetMin || 1
    const distance = Math.abs(project.budget - mid)
    budgetFit = Math.max(0, Math.round(100 - (distance / range) * 100))
  } else if (freelancer.hourlyRate != null) {
    // Very roughly: if project budget > hourly rate * 10, it's a sizeable project
    const rough = Math.min(1, project.budget / (freelancer.hourlyRate * 40)) * 100
    budgetFit = Math.round(rough)
  }

  // ── 5. Client Trust (0–100) ────────────────────────────────
  let clientTrust = 40 // neutral base
  if (project.client) {
    if (project.client.isVerified) clientTrust += 30
    if (project.client.averageRating != null) {
      // averageRating = 0–5 → add up to 20 points
      clientTrust += Math.round((project.client.averageRating / 5) * 20)
    }
    if (project.client.hireRate != null) {
      // hireRate = 0–1 → add up to 10 points
      clientTrust += Math.round(project.client.hireRate * 10)
    }
  }
  clientTrust = Math.min(100, clientTrust)

  // ── 6. Freelancer Success (0–100) ──────────────────────────
  // Own track record — higher = better. Punish high dispute ratio.
  let freelancerSuccess = 40
  freelancerSuccess += Math.min(40, freelancer.completedContracts * 4)
  if (freelancer.averageRating != null) {
    freelancerSuccess += Math.round((freelancer.averageRating / 5) * 10)
  }
  freelancerSuccess -= Math.round(freelancer.disputeRatio * 30)
  freelancerSuccess = Math.max(0, Math.min(100, freelancerSuccess))

  // ── 7. Activity (0–100) ─────────────────────────────────────
  // Penalise if freelancer has sent tons of proposals recently
  // (spam prevention: prefer quality bids over mass-apply).
  const recentActivityPenalty = Math.min(freelancer.recentProposalCount, 20) * 2
  const activity = Math.max(0, 100 - recentActivityPenalty)

  // ── 8. Personal Boost (0–0.5 additive multiplier) ──────────
  // Applied on top of the weighted score if there is a behavioral signal.
  let personalBoost = 0
  if (
    project.category?.slug &&
    freelancer.preferredCategories.includes(project.category.slug)
  ) {
    personalBoost += 0.15 // actively interests the freelancer
  }
  if (freelancer.savedProjectIds.includes(project.id)) {
    personalBoost += 0.10 // previously saved = strong interest
  }
  if (freelancer.viewedProjectIds.includes(project.id)) {
    personalBoost -= 0.05 // already seen = mild de-boost (prevent repetition)
  }

  // ── 9. Weighted Final Score ─────────────────────────────────
  const weighted =
    skillMatch         * SCORING_WEIGHTS.skillMatch         +
    freshness          * SCORING_WEIGHTS.freshness           +
    competition        * SCORING_WEIGHTS.competition         +
    budgetFit          * SCORING_WEIGHTS.budgetFit           +
    clientTrust        * SCORING_WEIGHTS.clientTrust         +
    freelancerSuccess  * SCORING_WEIGHTS.freelancerSuccess   +
    activity           * SCORING_WEIGHTS.activity

  const boosted = weighted * (1 + personalBoost)
  const score  = Math.min(100, Math.round(boosted))

  return {
    score,
    matchPercentage: skillMatch, // shown directly on card
    isExploration: false,
    scoreBreakdown: {
      skillMatch,
      freshness,
      competition,
      budgetFit,
      clientTrust,
      freelancerSuccess,
      activity,
      personalBoost,
    },
  }
}
