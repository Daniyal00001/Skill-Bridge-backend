/**
 * browseFreelancers.types.ts
 * location: backend/src/modules/browse-freelancers/browseFreelancers.types.ts
 *
 * Central type definitions for Browse Freelancers module.
 * Mirror of browse.types.ts but for Client → Freelancer direction.
 */

// Raw freelancer shape from Prisma
export interface RawFreelancer {
  id: string;
  userId: string;
  fullName: string;
  bio?: string | null;
  tagline?: string | null;
  location?: string | null;
  region?: string | null;
  timezone?: string | null;
  hourlyRate?: number | null;
  experienceLevel: "ENTRY" | "MID" | "SENIOR" | "EXPERT";
  availability: "AVAILABLE" | "BUSY" | "UNAVAILABLE";
  profileCompletion: number;
  profileCompletionScore: number;
  skillTokenBalance: number;
  github?: string | null;
  linkedin?: string | null;
  portfolio?: string | null;
  website?: string | null;
  languages?: any;
  averageRating?: number | null;
  totalReviews: number;
  completedContracts: number;
  lastLoginAt?: Date | null;
  createdAt?: Date | null;

  // Relations
  skills: Array<{
    skill: { id: string; name: string; category: string };
    proficiencyLevel: number;
  }>;
  portfolioItems: Array<{
    id: string;
    title: string;
    imageUrl?: string | null;
    techStack: string[];
  }>;
  user: {
    profileImage?: string | null;
    isIdVerified: boolean;
    isPaymentVerified: boolean;
  };
}

// Client snapshot for scoring
export interface ClientSnapshot {
  id: string;
  requiredSkills: string[]; // from current project or preference
  budgetMin?: number;
  budgetMax?: number;
  hourlyBudgetMin?: number;
  hourlyBudgetMax?: number;
  preferredExpLevel?: string;
  preferredRegion?: string;
  locationPref?: string;
  preferredLanguage?: string | null;
  spokenLanguages: string[];
  preferredCategories: string[];
  viewedFreelancerIds: string[];
  savedFreelancerIds: string[];
  hiredFreelancerIds: string[]; // past hired freelancers
}

// Scored freelancer ready for feed
export interface ScoredFreelancer extends RawFreelancer {
  score: number;
  matchPercentage: number;
  isExploration: boolean;
  scoreBreakdown: {
    skillMatch: number;
    rating: number;
    availability: number;
    budgetFit: number;
    successScore: number;
    activityScore: number;
    profileScore: number;
  };
}

// Filters from frontend
export interface FreelancerBrowseFilters {
  search?: string;
  skills?: string[];
  experienceLevel?: "ENTRY" | "MID" | "SENIOR" | "EXPERT";
  availability?: "AVAILABLE" | "BUSY" | "UNAVAILABLE";
  hourlyRateMin?: number;
  hourlyRateMax?: number;
  location?: string;
  region?: string;
  minRating?: number;
  hasPortfolio?: boolean;
  isVerified?: boolean;
  categorySlug?: string;
  level?: "entry" | "beginner" | "intermediate" | "senior" | "expert";
}

// Sort options
export type FreelancerSortOption =
  | "best_match"
  | "top_rated"
  | "most_experienced"
  | "lowest_rate"
  | "highest_rate"
  | "recently_active";

export const VALID_FREELANCER_SORT_OPTIONS: FreelancerSortOption[] = [
  "best_match",
  "top_rated",
  "most_experienced",
  "lowest_rate",
  "highest_rate",
  "recently_active",
];

// Paginated response
export interface FreelancerBrowseResponse {
  freelancers: ScoredFreelancer[];
  sections: {
    topRated: ScoredFreelancer[];
    recentlyActive: ScoredFreelancer[];
    newTalent: ScoredFreelancer[];
    highlyExperienced: ScoredFreelancer[];
    perfectBudgetMatch: ScoredFreelancer[];
  };
  cursor?: string;
  hasMore: boolean;
  total: number;
  cachedAt?: number;
}

// Scoring weights
export const FREELANCER_SCORING_WEIGHTS = {
  skillMatch: 0.3,
  rating: 0.25,
  availability: 0.2,
  budgetFit: 0.1,
  successScore: 0.1,
  activityScore: 0.05,
} as const;

export const FREELANCER_EXPLORATION_RATIO = 0.1; // for new freelancers
export const FREELANCER_CACHE_TTL_SECONDS = 120; // 2 min (freelancer data changes slower)
export const FREELANCER_FETCH_POOL_SIZE = 150;
export const FREELANCER_PAGE_SIZE = 20;
