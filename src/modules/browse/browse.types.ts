/**
 * browse.types.ts
 * ─────────────────────────────────────────────────────────────────
 * WHY HERE: Centralized type definitions for the entire browse module.
 * Keeping types in one place means if Prisma schema changes, we only
 * update types here — not scattered across 5 files.
 * ─────────────────────────────────────────────────────────────────
 */

// ── Raw project shape coming from Prisma/MongoDB ──────────────────
export interface RawProject {
  id: string;
  title: string;
  description: string;
  status: string;
  budget: number;
  budgetType: "fixed" | "hourly";
  deadline: Date;
  createdAt: Date;
  proposalCount: number;
  maxProposals?: number;
  experienceLevel: "ENTRY" | "MID" | "SENIOR" | "EXPERT";
  size: "SMALL" | "MEDIUM" | "LARGE";
  locationPref?: string;
  isAiScoped?: boolean;

  category: { id: string; name: string; slug: string };
  skills: Array<{ skill: { id: string; name: string } }>;

  client: {
    id: string;
    fullName: string;
    company?: string;
    isVerified: boolean;
    averageRating?: number;
    totalHires?: number;
    hireRate?: number; // 0–1
  };
}

// ── Freelancer snapshot used for scoring ──────────────────────────
export interface FreelancerSnapshot {
  id: string;
  skillNames: string[];          // ["React", "Node.js", ...]
  experienceLevel: "ENTRY" | "MID" | "SENIOR" | "EXPERT";
  hourlyRate?: number;
  profileCompletionScore: number; // 0–100
  completedContracts: number;
  averageRating?: number;
  disputeRatio: number;           // 0–1 (lower is better)
  lastLoginAt: Date;
  recentProposalCount: number;    // last 30 days
  // Behavioral signals
  preferredCategories: string[];  // category slugs with high interaction
  preferredBudgetMin?: number;
  preferredBudgetMax?: number;
  appliedProjectIds: string[];
  savedProjectIds: string[];
  viewedProjectIds: string[];
}

// ── Scored project ready for the feed ─────────────────────────────
export interface ScoredProject extends RawProject {
  score: number;            // 0–100 final weighted score
  scoreBreakdown: {
    skillMatch: number;     // 0–100
    freshness: number;      // 0–100
    competition: number;    // 0–100
    budgetFit: number;      // 0–100
    clientTrust: number;    // 0–100
    freelancerSuccess: number; // 0–100
    activity: number;       // 0–100
    personalBoost: number;  // 0–1 multiplier from behavior
  };
  matchPercentage: number;  // shown on UI card
  isExploration: boolean;   // true = injected low-visibility project
}

// ── Filter options accepted from frontend ─────────────────────────
export interface BrowseFilters {
  search?: string;
  categorySlug?: string;
  skills?: string[];
  budgetMin?: number;
  budgetMax?: number;
  experienceLevel?: "ENTRY" | "MID" | "SENIOR" | "EXPERT";
  size?: "SMALL" | "MEDIUM" | "LARGE";
  clientVerified?: boolean;
  isAiScoped?: boolean;
  proposalCountMax?: number;
  locationPref?: string;
}

// ── Sort options ───────────────────────────────────────────────────
export type SortOption =
  | "best_match"      // default — uses FinalScore
  | "newest"
  | "lowest_proposals"
  | "highest_budget"
  | "deadline_soon";

// ── Paginated response ─────────────────────────────────────────────
export interface BrowseResponse {
  projects: ScoredProject[];
  sections: {
    recommended: ScoredProject[];
    newProjects: ScoredProject[];
    lowCompetition: ScoredProject[];
    highBudget: ScoredProject[];
    similarToSaved: ScoredProject[];
  };
  cursor?: string;  // for cursor-based pagination
  hasMore: boolean;
  total: number;
  cachedAt?: number; // Unix ms — so UI can show "updated X seconds ago"
}

// ── Weights used in scoring formula ───────────────────────────────
// Exported so tests can override weights easily
export const SCORING_WEIGHTS = {
  skillMatch: 0.40,
  freshness: 0.20,
  competition: 0.15,
  budgetFit: 0.10,
  clientTrust: 0.05,
  freelancerSuccess: 0.05,
  activity: 0.05,
} as const;

// ── Exploration injection ratio ────────────────────────────────────
export const EXPLORATION_RATIO = 0.10; // 10% of feed = random/low-visibility
export const NEW_PROJECT_BOOST_HOURS = 6; // boost projects < 6 hours old
export const CACHE_TTL_SECONDS = 60;