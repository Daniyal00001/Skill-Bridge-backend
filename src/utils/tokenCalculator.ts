/**
 * SkillToken Cost Calculator
 *
 * Calculates the number of SkillTokens required to submit a proposal
 * based on the project's budget, experience level, competition, and size.
 */

export interface TokenCostInput {
  budget: number
  budgetType?: string // 'fixed' | 'hourly'
  experienceLevel: string // 'entry' | 'intermediate' | 'expert' | 'senior'
  proposalCount: number
  isFeatured?: boolean
  projectSize: string // 'SMALL' | 'MEDIUM' | 'LARGE'
}

export interface TokenCostBreakdown {
  baseCost: number
  experienceMultiplier: number
  afterMultiplier: number
  featuredAdjustment: number
  competitionAdjustment: number
  sizeAdjustment: number
  totalCost: number
}

/**
 * Calculate token cost for submitting a proposal
 */
export function calculateTokenCost(input: TokenCostInput): number {
  return calculateTokenCostWithBreakdown(input).totalCost
}

/**
 * Calculate token cost with full breakdown (for UI display)
 */
export function calculateTokenCostWithBreakdown(input: TokenCostInput): TokenCostBreakdown {
  const { budget, budgetType = 'fixed', experienceLevel, proposalCount, isFeatured = false, projectSize } = input

  // ── Step 1: Base cost by budget ──────────────────────────────────────
  let baseCost: number

  if (budgetType.toLowerCase() === 'hourly') {
    if (budget < 5) {
      baseCost = 1
    } else if (budget < 10) {
      baseCost = 2
    } else if (budget < 20) {
      baseCost = 3
    } else if (budget < 40) {
      baseCost = 5
    } else if (budget < 80) {
      baseCost = 7
    } else {
      baseCost = 10
    }
  } else {
    // Fixed Price (default)
    if (budget < 50) {
      baseCost = 2
    } else if (budget < 100) {
      baseCost = 4
    } else if (budget < 200) {
      baseCost = 6
    } else if (budget < 500) {
      baseCost = 8
    } else if (budget < 1000) {
      baseCost = 12
    } else {
      baseCost = 16
    }
  }

  // ── Step 2: Experience level multiplier ──────────────────────────────
  let experienceMultiplier: number
  const level = experienceLevel?.toLowerCase() || 'entry'
  if (level === 'expert' || level === 'senior') {
    experienceMultiplier = 1.5
  } else if (level === 'intermediate' || level === 'mid') {
    experienceMultiplier = 1.25
  } else {
    experienceMultiplier = 1.0 // entry
  }

  const afterMultiplier = Math.ceil(baseCost * experienceMultiplier)

  // ── Step 3: Additive adjustments ─────────────────────────────────────
  const featuredAdjustment = isFeatured ? 2 : 0
  const competitionAdjustment = proposalCount > 20 ? 1 : 0
  const sizeAdjustment = projectSize?.toUpperCase() === 'LARGE' ? 1 : 0

  const totalCost = afterMultiplier + featuredAdjustment + competitionAdjustment + sizeAdjustment

  return {
    baseCost,
    experienceMultiplier,
    afterMultiplier,
    featuredAdjustment,
    competitionAdjustment,
    sizeAdjustment,
    totalCost,
  }
}
