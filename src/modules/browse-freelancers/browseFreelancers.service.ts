/**
 * browseFreelancers.service.ts
 * location: backend/src/modules/browse-freelancers/browseFreelancers.service.ts
 *
 * Brain of Browse Freelancers.
 * Flow: Cache check → Client snapshot → DB fetch → Score → Sort → Inject → Sections → Cache → Paginate
 */

import { PrismaClient } from "@prisma/client";
import {
  ClientSnapshot,
  FreelancerBrowseFilters,
  FreelancerBrowseResponse,
  FreelancerSortOption,
  RawFreelancer,
  ScoredFreelancer,
  FREELANCER_CACHE_TTL_SECONDS,
  FREELANCER_EXPLORATION_RATIO,
  FREELANCER_FETCH_POOL_SIZE,
  FREELANCER_PAGE_SIZE,
} from "./browseFreelancers.types";
import { scoreFreelancer } from "./browseFreelancers.scoring";
import redis from "../../config/redis";

// ── LEVEL COMPUTATION (mirrors frontend levelUtils.ts) ───────────
function computeFreelancerLevel(
  earnings: number,
  clients: number,
  projects: number,
  rating: number,
): string {
  if (earnings >= 5000 && projects >= 30 && rating >= 4.5) return "expert";
  if (earnings >= 2000 && projects >= 15 && rating >= 4) return "senior";
  if (earnings >= 500 && clients >= 5 && projects >= 10) return "intermediate";
  if (earnings >= 100 && clients >= 3) return "beginner";
  return "entry";
}

// ── MAIN ENTRY POINT ─────────────────────────────────────────────
export async function getBrowseFreelancersFeed(
  prisma: PrismaClient,
  clientId: string,
  filters: FreelancerBrowseFilters,
  sort: FreelancerSortOption,
  cursor?: string,
): Promise<FreelancerBrowseResponse> {
  // 1. Cache key
  const cacheKey = buildCacheKey(clientId, filters, sort);

  // 2. Check Redis
  try {
    const cached = await redis.get(cacheKey);
    if (cached) {
      return paginateResponse(
        JSON.parse(cached) as FreelancerBrowseResponse,
        cursor,
      );
    }
  } catch {
    /* Redis down — continue to DB */
  }

  // 3. Client snapshot
  const client = await getClientSnapshot(prisma, clientId);
  if (!client) throw new Error("Client not found");

  // 4. Fetch eligible freelancers
  const rawFreelancers = await fetchEligibleFreelancers(prisma, filters);

  // 5. Score
  let scored: ScoredFreelancer[] = rawFreelancers.map((f) => ({
    ...f,
    ...scoreFreelancer(f, client),
  }));

  // 5b. Apply level filter if specified (post-score, since level is computed)
  if (filters.level) {
    scored = scored.filter((f) => {
      const level = computeFreelancerLevel(
        0, // totalEarnings not in browse (use 0 — level filter based on available fields)
        f.totalReviews ?? 0,
        f.completedContracts ?? 0,
        f.averageRating ?? 0,
      );
      return level === filters.level;
    });
  }

  // 6. Sort
  scored = applySorting(scored, sort);

  // 7. Inject exploration
  scored = injectExploration(scored);

  // 8. Build sections
  const sections = buildSections(scored);

  // 9. Build response
  const fullResponse: FreelancerBrowseResponse = {
    freelancers: scored,
    sections,
    hasMore: scored.length > FREELANCER_PAGE_SIZE,
    total: scored.length,
    cachedAt: Date.now(),
  };

  // 10. Cache
  try {
    await redis.setEx(
      cacheKey,
      FREELANCER_CACHE_TTL_SECONDS,
      JSON.stringify(fullResponse),
    );
  } catch {
    /* non-fatal */
  }

  return paginateResponse(fullResponse, cursor);
}

// ── FETCH ELIGIBLE FREELANCERS ───────────────────────────────────
async function fetchEligibleFreelancers(
  prisma: PrismaClient,
  filters: FreelancerBrowseFilters,
): Promise<RawFreelancer[]> {
  const where: any = {
    // Only show AVAILABLE or BUSY freelancers
    availability: filters.availability
      ? filters.availability
      : { in: ["AVAILABLE", "BUSY"] },
    // Must have at least started profile
    profileCompletion: { gte: 30 },
  };

  // Search — name, tagline, bio
  if (filters.search) {
    where.OR = [
      { fullName: { contains: filters.search, mode: "insensitive" } },
      { tagline: { contains: filters.search, mode: "insensitive" } },
      { bio: { contains: filters.search, mode: "insensitive" } },
    ];
  }

  // Experience level
  if (filters.experienceLevel) {
    where.experienceLevel = filters.experienceLevel;
  }

  // Hourly rate range
  if (
    filters.hourlyRateMin !== undefined ||
    filters.hourlyRateMax !== undefined
  ) {
    where.hourlyRate = {};
    if (filters.hourlyRateMin !== undefined)
      where.hourlyRate.gte = filters.hourlyRateMin;
    if (filters.hourlyRateMax !== undefined)
      where.hourlyRate.lte = filters.hourlyRateMax;
  }

  // Location filter
  if (filters.location) {
    where.location = { contains: filters.location, mode: "insensitive" };
  }

  // Region filter (from schema: region field on FreelancerProfile)
  if (filters.region) {
    where.region = { contains: filters.region, mode: "insensitive" };
  }

  // Minimum rating filter
  if (filters.minRating !== undefined) {
    where.averageRating = { gte: filters.minRating };
  }

  // Has portfolio items
  if (filters.hasPortfolio) {
    where.portfolioItems = { some: {} };
  }

  if (filters.isVerified) {
    where.user = { isIdVerified: true };
  }

  // Skill filter
  if (filters.skills?.length) {
    where.skills = {
      some: {
        skill: { name: { in: filters.skills } },
      },
    };
  }

  const rows = await prisma.freelancerProfile.findMany({
    where,
    take: FREELANCER_FETCH_POOL_SIZE,
    orderBy: { averageRating: "desc" }, // initial DB order
    select: {
      id: true,
      userId: true,
      fullName: true,
      bio: true,
      tagline: true,
      location: true,
      region: true,
      timezone: true,
      hourlyRate: true,
      experienceLevel: true,
      availability: true,
      languages: true,
      profileCompletion: true,
      profileCompletionScore: true,
      skillTokenBalance: true,
      github: true,
      linkedin: true,
      portfolio: true,
      website: true,
      averageRating: true,
      totalReviews: true,
      lastLoginAt: true,
      createdAt: true,
      user: {
        select: {
          profileImage: true,
          isIdVerified: true,
          isPaymentVerified: true,
        },
      },
      skills: {
        include: {
          skill: {
            select: { id: true, name: true, category: true },
          },
        },
      },
      portfolioItems: {
        select: {
          id: true,
          title: true,
          imageUrl: true,
          techStack: true,
        },
        take: 3,
      },
      contracts: {
        where: { status: "COMPLETED" },
        select: { id: true },
      },
    },
  });

  // Map to RawFreelancer shape
  return (rows as any[]).map((row) => ({
    ...row,
    completedContracts: row.contracts?.length ?? 0,
    contracts: undefined, // remove raw contracts array
  })) as RawFreelancer[];
}

// ── CLIENT SNAPSHOT ──────────────────────────────────────────────
async function getClientSnapshot(
  prisma: PrismaClient,
  clientUserId: string,
): Promise<ClientSnapshot | null> {
  const client = await prisma.clientProfile.findUnique({
    where: { userId: clientUserId },
    include: {
      projects: {
        where: { status: { in: ["OPEN", "IN_PROGRESS"] } },
        include: {
          skills: {
            include: { skill: { select: { name: true } } },
          },
        },
        take: 3, // latest active projects for skill signals
        orderBy: { createdAt: "desc" },
      },
    },
  });

  if (!client) return null;

  const c = client as any;

  // Extract required skills from active projects
  const requiredSkills: string[] = [];
  for (const project of c.projects ?? []) {
    for (const ps of project.skills ?? []) {
      const name = ps.skill?.name;
      if (name && !requiredSkills.includes(name)) {
        requiredSkills.push(name);
      }
    }
  }

  // Get previously hired freelancer IDs
  const hiredContracts = await prisma.contract.findMany({
    where: {
      project: { clientProfileId: c.id },
      status: "COMPLETED",
    },
    select: { freelancerProfileId: true },
    take: 50,
  });
  const hiredFreelancerIds = hiredContracts.map((c) => c.freelancerProfileId);

  return {
    id: c.id,
    requiredSkills,
    budgetMin: undefined,
    budgetMax: undefined,
    hourlyBudgetMin: c.hourlyBudgetMin ?? undefined,
    hourlyBudgetMax: c.hourlyBudgetMax ?? undefined,
    preferredExpLevel: c.preferredExpLevel ?? undefined,
    preferredRegion: c.preferredRegion ?? undefined,
    locationPref: c.locationPref ?? undefined,
    preferredLanguage: (c as any).language ?? undefined,
    spokenLanguages: (c as any).spokenLanguages ?? [],
    preferredCategories: [],
    viewedFreelancerIds: [],
    savedFreelancerIds: [],
    hiredFreelancerIds,
  };
}

// ── SORT ─────────────────────────────────────────────────────────
function applySorting(
  freelancers: ScoredFreelancer[],
  sort: FreelancerSortOption,
): ScoredFreelancer[] {
  switch (sort) {
    case "best_match":
      return [...freelancers].sort((a, b) => b.score - a.score);
    case "top_rated":
      return [...freelancers].sort(
        (a, b) => (b.averageRating ?? 0) - (a.averageRating ?? 0),
      );
    case "most_experienced":
      return [...freelancers].sort(
        (a, b) => b.completedContracts - a.completedContracts,
      );
    case "lowest_rate":
      return [...freelancers].sort(
        (a, b) => (a.hourlyRate ?? 999) - (b.hourlyRate ?? 999),
      );
    case "highest_rate":
      return [...freelancers].sort(
        (a, b) => (b.hourlyRate ?? 0) - (a.hourlyRate ?? 0),
      );
    case "recently_active":
      return [...freelancers].sort((a, b) => {
        const aTime = a.lastLoginAt ? new Date(a.lastLoginAt).getTime() : 0;
        const bTime = b.lastLoginAt ? new Date(b.lastLoginAt).getTime() : 0;
        return bTime - aTime;
      });
    default:
      return freelancers;
  }
}

// ── EXPLORATION INJECTION ────────────────────────────────────────
// New freelancers with few reviews get fair exposure
function injectExploration(sorted: ScoredFreelancer[]): ScoredFreelancer[] {
  const result = [...sorted];
  const explorationCount = Math.floor(
    result.length * FREELANCER_EXPLORATION_RATIO,
  );

  const topIds = new Set(result.slice(0, 40).map((f) => f.id));
  const candidates = result.filter((f) => !topIds.has(f.id));
  const shuffled = candidates.sort(() => Math.random() - 0.5);
  const picks = shuffled.slice(0, explorationCount).map((f) => ({
    ...f,
    isExploration: true,
  }));

  picks.forEach((f) => {
    const insertAt = Math.floor(Math.random() * Math.min(40, result.length));
    result.splice(insertAt, 0, f);
  });

  return result;
}

// ── BUILD SECTIONS ───────────────────────────────────────────────
function buildSections(freelancers: ScoredFreelancer[]) {
  const SECTION_SIZE = 6;
  const now = Date.now();
  const THIRTY_DAYS = 30 * 86_400_000;

  return {
    // Top rated (4+ rating with reviews)
    topRated: [...freelancers]
      .filter((f) => (f.averageRating ?? 0) >= 4 && f.totalReviews >= 2)
      .sort((a, b) => (b.averageRating ?? 0) - (a.averageRating ?? 0))
      .slice(0, SECTION_SIZE),

    // Active in last 7 days
    recentlyActive: [...freelancers]
      .filter((f) => {
        if (!f.lastLoginAt) return false;
        return now - new Date(f.lastLoginAt).getTime() < 7 * 86_400_000;
      })
      .sort((a, b) => b.score - a.score)
      .slice(0, SECTION_SIZE),

    // New talent — joined in last 30 days, no completed contracts
    newTalent: [...freelancers]
      .filter((f) => {
        const isNew = f.createdAt
          ? now - new Date(f.createdAt).getTime() < THIRTY_DAYS
          : false;
        return isNew && f.completedContracts === 0;
      })
      .sort((a, b) => b.score - a.score)
      .slice(0, SECTION_SIZE),

    // Highly experienced (5+ contracts)
    highlyExperienced: [...freelancers]
      .filter((f) => f.completedContracts >= 5)
      .sort((a, b) => b.completedContracts - a.completedContracts)
      .slice(0, SECTION_SIZE),

    // Budget match — available and fits rate
    perfectBudgetMatch: [...freelancers]
      .filter((f) => f.scoreBreakdown.budgetFit >= 80)
      .sort((a, b) => b.scoreBreakdown.budgetFit - a.scoreBreakdown.budgetFit)
      .slice(0, SECTION_SIZE),
  };
}

// ── CURSOR PAGINATION ────────────────────────────────────────────
function paginateResponse(
  response: FreelancerBrowseResponse,
  cursor?: string,
): FreelancerBrowseResponse {
  const all = response.freelancers;
  let startIndex = 0;

  if (cursor) {
    const idx = all.findIndex((f) => f.id === cursor);
    startIndex = idx >= 0 ? idx + 1 : 0;
  }

  const page = all.slice(startIndex, startIndex + FREELANCER_PAGE_SIZE);
  const nextItem = all[startIndex + FREELANCER_PAGE_SIZE];

  return {
    ...response,
    freelancers: page,
    cursor: nextItem?.id,
    hasMore: !!nextItem,
  };
}

// ── CACHE KEY ────────────────────────────────────────────────────
function buildCacheKey(
  clientId: string,
  filters: FreelancerBrowseFilters,
  sort: FreelancerSortOption,
): string {
  const hash = Buffer.from(JSON.stringify(filters))
    .toString("base64")
    .slice(0, 20);
  return `browse-freelancers:v1:${clientId}:${sort}:${hash}`;
}
