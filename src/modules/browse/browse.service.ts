/**
 * browse.service.ts
 * ─────────────────────────────────────────────────────────────────
 * WHY HERE: This is the "brain" of the Browse system.
 * It orchestrates: DB fetch → filter → score → explore inject → sort → cache.
 * Controllers stay thin — they just call this service.
 *
 * Architecture decisions:
 *  - PrismaClient injected (not imported directly) → testable
 *  - Redis cache checked FIRST before any DB work
 *  - Exploration injection AFTER scoring so scores are real
 *  - Sections built from the same scored array — no extra DB calls
 * ─────────────────────────────────────────────────────────────────
 */

import { PrismaClient } from "@prisma/client";
import {
  BrowseFilters,
  BrowseResponse,
  FreelancerSnapshot,
  RawProject,
  ScoredProject,
  SortOption,
  EXPLORATION_RATIO,
  CACHE_TTL_SECONDS,
  InteractionType,
} from "./browse.types";
import { scoreProject } from "./browse.scoring";
import { getCachedFeed, setCachedFeed } from "./browse.cache";

// ── How many projects to fetch from DB before ranking ─────────────
// We fetch MORE than page size so ranking has a good pool to work with.
const FETCH_POOL_SIZE = 200;
const PAGE_SIZE = 25;

// ─────────────────────────────────────────────────────────────────
// MAIN ENTRY POINT
// Called by browse.controller.ts
// ─────────────────────────────────────────────────────────────────
export async function getBrowseFeed(
  prisma: PrismaClient,
  freelancerId: string,
  filters: BrowseFilters,
  sort: SortOption,
  cursor?: string, // for cursor-based pagination
): Promise<BrowseResponse> {
  // ── 1. Build cache key ─────────────────────────────────────────
  // Key includes freelancer + filters so each freelancer gets personalized cache.
  // Cursor NOT in key — pagination handled post-cache.
  const cacheKey = buildCacheKey(freelancerId, filters, sort);

  // ── 2. Check Redis cache ───────────────────────────────────────
  const cached = await getCachedFeed(cacheKey);
  if (cached) {
    return paginateResponse(cached, cursor);
  }

  // ── 3. Fetch freelancer snapshot (for scoring) ─────────────────
  const freelancer = await getFreelancerSnapshot(prisma, freelancerId);
  if (!freelancer) throw new Error("Freelancer not found");

  // ── 4. Fetch eligible projects from DB ────────────────────────
  const rawProjects = await fetchEligibleProjects(prisma, freelancer, filters);

  // ── 5. Score every project ────────────────────────────────────
  let scoredProjects: ScoredProject[] = rawProjects.map((project) => ({
    ...project,
    ...scoreProject(project, freelancer),
  }));

  // ── 6. Sort ───────────────────────────────────────────────────
  scoredProjects = applySorting(scoredProjects, sort);

  // ── 7. Inject exploration projects (5–15%) ────────────────────
  // We inject AFTER sorting so the exploration slots are randomly placed
  // among real results, not always at the bottom.
  scoredProjects = injectExploration(scoredProjects, rawProjects);

  // ── 8. Build recommendation sections ─────────────────────────
  const sections = buildSections(scoredProjects, freelancer);

  // ── 9. Build full response ────────────────────────────────────
  const fullResponse: BrowseResponse = {
    projects: scoredProjects,
    sections,
    hasMore: scoredProjects.length > PAGE_SIZE,
    total: scoredProjects.length,
    cachedAt: Date.now(),
  };

  // ── 10. Cache result ──────────────────────────────────────────
  await setCachedFeed(cacheKey, fullResponse, CACHE_TTL_SECONDS);

  return paginateResponse(fullResponse, cursor);
}

// ─────────────────────────────────────────────────────────────────
// FETCH ELIGIBLE PROJECTS
// Only fetch what the freelancer is ALLOWED to see and apply to.
// All eligibility rules in WHERE clause — not post-filter in JS.
// WHY: Filtering in DB is orders of magnitude faster than JS loops.
// ─────────────────────────────────────────────────────────────────
async function fetchEligibleProjects(
  prisma: PrismaClient,
  freelancer: FreelancerSnapshot,
  filters: BrowseFilters,
): Promise<RawProject[]> {
  const now = new Date();

  const where: any = {
    // Core eligibility — non-negotiable
    status: "OPEN",
    // Bug #7 fix: remove invalid $queryRaw filter — we just filter by OPEN status
    // (maxProposals field doesn't exist on Project model in schema)
    // Freelancer hasn't already applied — Bug #4 fix: use freelancerProfileId not freelancerId
    proposals: {
      none: { freelancerProfileId: freelancer.id },
    },
  };

  // deadline filter: must be in the future AND not null
  where.deadline = { gt: now, not: null };

  // Search: MongoDB Prisma does NOT support mode:"insensitive".
  // We use a plain contains — exact substring match (case-sensitive).
  // For full-text search, use MongoDB Atlas Search or a regex workaround.
  if (filters.search) {
    where.AND = [
      {
        OR: [
          { title: { contains: filters.search } },
          { description: { contains: filters.search } },
        ],
      },
    ];
  }

  if (filters.categorySlug) {
    where.category = { slug: filters.categorySlug };
  }

  if (filters.budgetMin || filters.budgetMax) {
    where.budget = {};
    if (filters.budgetMin) where.budget.gte = filters.budgetMin;
    if (filters.budgetMax) where.budget.lte = filters.budgetMax;
  }

  if (filters.experienceLevel) {
    where.experienceLevel = filters.experienceLevel;
  }

  if (filters.size) {
    where.size = filters.size;
  }

  // Bug #5 fix: correct relation name is clientProfile (not client)
  if (filters.clientVerified) {
    where.clientProfile = {
      user: {
        OR: [{ isPaymentVerified: true }, { isIdVerified: true }],
      },
    };
  }

  if (filters.locationPref) {
    where.locationPref = filters.locationPref;
  }

  if (filters.proposalCountMax != null) {
    where.proposalCount = { lte: filters.proposalCountMax };
  }

  // Skill filter — project must require AT LEAST ONE of the provided skills
  if (filters.skills?.length) {
    where.skills = {
      some: {
        skill: { name: { in: filters.skills } },
      },
    };
  }

  // Bug #5 fix: use clientProfile (correct Prisma relation name for Project)
  const rawRows = await prisma.project.findMany({
    where,
    take: FETCH_POOL_SIZE,
    orderBy: { createdAt: "desc" }, // initial DB order, re-ranked in memory
    include: {
      category: { select: { id: true, name: true, slug: true } },
      skills: {
        include: { skill: { select: { id: true, name: true } } },
      },
      clientProfile: {
        select: {
          id: true,
          fullName: true,
          company: true,
          averageRating: true,
          totalHires: true,
          hireRate: true,
        },
      },
      locationObj: { select: { name: true } },
    },
  });

  // Bug #5 fix: remap clientProfile → client to match RawProject type in scoring engine
  const projects: RawProject[] = (rawRows as any[]).map((row) => ({
    ...row,
    client: row.clientProfile
      ? {
          id: row.clientProfile.id,
          fullName: row.clientProfile.fullName,
          company: row.clientProfile.company,
          isVerified: false, // not in ClientProfile schema; extend if needed
          averageRating: row.clientProfile.averageRating,
          totalHires: row.clientProfile.totalHires,
          hireRate: row.clientProfile.hireRate,
        }
      : { id: "", fullName: "Unknown", isVerified: false },
  }));

  return projects;
}

// ─────────────────────────────────────────────────────────────────
// FREELANCER SNAPSHOT
// Fetches everything needed for scoring in ONE query.
// WHY snapshot pattern: We don't want scoring functions making DB calls.
// ─────────────────────────────────────────────────────────────────
async function getFreelancerSnapshot(
  prisma: PrismaClient,
  freelancerId: string,
): Promise<FreelancerSnapshot | null> {
  // Bug #6 fix: include savedProjects so savedIds work
  // Bug #5 fix: contracts are on Contract model (no direct relation on FreelancerProfile)
  //             so we query them separately via prisma.contract.findMany
  const freelancer = await prisma.freelancerProfile.findUnique({
    where: { userId: freelancerId },
    include: {
      skills: { include: { skill: true } },
      // Bug #6 fix: savedProjects MUST be included
      savedProjects: { select: { projectId: true } },
      proposals: {
        where: {
          submittedAt: { gte: new Date(Date.now() - 30 * 86_400_000) },
        },
        select: { id: true, projectId: true },
      },
      // Behavioral tracking data
      browseInteractions: {
        orderBy: { createdAt: "desc" },
        take: 100,
        select: { projectId: true, type: true, categorySlug: true, createdAt: true },
      },
    },
  });

  if (!freelancer) return null;

  // Cast to any so TypeScript doesn't complain about Prisma-included relations
  const f = freelancer as any;

  const completedContractsRows = await prisma.contract.findMany({
    where: { freelancerProfileId: f.id, status: "COMPLETED" },
    select: { id: true },
  });
  const completedContracts = completedContractsRows.length;

  // averageRating: calculate from Review model
  const reviews = await prisma.review.findMany({
    where: { receiverId: freelancer.userId, isRevealed: true },
    select: { rating: true },
  });
  const averageRating =
    reviews.length > 0
      ? reviews.reduce((sum, r) => sum + r.rating, 0) / reviews.length
      : undefined;

  // Build preferred categories from interaction history
  const categoryClicks: Record<string, number> = {};
  for (const interaction of (f.browseInteractions ?? []) as any[]) {
    if (interaction.categorySlug) {
      categoryClicks[interaction.categorySlug] =
        (categoryClicks[interaction.categorySlug] ?? 0) + 1;
    }
  }
  const preferredCategories = Object.entries(categoryClicks)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5)
    .map(([slug]) => slug);

  const appliedIds = ((f.proposals ?? []) as any[]).map((p) => p.projectId);
  const savedIds = ((f.savedProjects ?? []) as any[]).map((p) => p.projectId);
  const viewedIds = ((f.browseInteractions ?? []) as any[])
    .filter((i) => i.type === "VIEW")
    .map((i) => i.projectId);

  return {
    id: f.id,
    skillNames: ((f.skills ?? []) as any[]).map((s) => s.skill.name),
    experienceLevel: f.experienceLevel as any,
    hourlyRate: f.hourlyRate ?? undefined,
    profileCompletionScore: f.profileCompletionScore ?? 50,
    completedContracts,
    averageRating,
    disputeRatio: f.disputeRatio ?? 0,
    lastLoginAt: f.lastLoginAt ?? new Date(),
    recentProposalCount: f.proposals?.length ?? 0,
    preferredCategories: [
      ...(f.preferredCategories || []), // Manual preferences from DB
      ...Object.entries(categoryClicks)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 5)
        .map(([slug]) => slug),
    ],
    preferredBudgetMin: f.preferredBudgetMin ?? undefined,
    preferredBudgetMax: f.preferredBudgetMax ?? undefined,
    appliedProjectIds: appliedIds,
    savedProjectIds: savedIds,
    viewedProjectIds: ((f.browseInteractions ?? []) as any[])
      .filter((i) => {
        const isView = i.type === "VIEW";
        const isRecent =
          new Date(i.createdAt).getTime() >= Date.now() - 7 * 86_400_000;
        return isView && isRecent;
      })
      .map((i) => i.projectId),
  };
}

// ─────────────────────────────────────────────────────────────────
// SORT
// ─────────────────────────────────────────────────────────────────
function applySorting(
  projects: ScoredProject[],
  sort: SortOption,
): ScoredProject[] {
  switch (sort) {
    case "best_match":
      return [...projects].sort((a, b) => b.score - a.score);
    case "newest":
      return [...projects].sort(
        (a, b) =>
          new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
      );
    case "lowest_proposals":
      return [...projects].sort((a, b) => a.proposalCount - b.proposalCount);
    case "highest_budget":
      return [...projects].sort((a, b) => b.budget - a.budget);
    case "deadline_soon":
      return [...projects].sort(
        (a, b) =>
          new Date(a.deadline).getTime() - new Date(b.deadline).getTime(),
      );
    default:
      return projects;
  }
}

// ─────────────────────────────────────────────────────────────────
// EXPLORATION INJECTION
// Randomly inject low-visibility projects (new clients, low-score)
// into feed so every project gets fair exposure.
// WHY: Without this, new clients with no ratings would never appear
// in ranked feeds — starving them of proposals entirely.
// ─────────────────────────────────────────────────────────────────
function injectExploration(
  sortedProjects: ScoredProject[],
  allRaw: RawProject[],
): ScoredProject[] {
  const result = [...sortedProjects];
  const totalSlots = result.length;
  const explorationCount = Math.floor(totalSlots * EXPLORATION_RATIO);

  // Projects not already in top results (low score = potential exploration candidates)
  const topIds = new Set(result.slice(0, 50).map((p) => p.id));
  const exploreCandidates = result.filter((p) => !topIds.has(p.id));

  // Shuffle and pick N
  const shuffled = exploreCandidates.sort(() => Math.random() - 0.5);
  const picks = shuffled.slice(0, explorationCount).map((p) => ({
    ...p,
    isExploration: true,
  }));

  // Inject at random positions in top 50
  picks.forEach((project) => {
    const insertAt = Math.floor(Math.random() * Math.min(50, result.length));
    result.splice(insertAt, 0, project);
  });

  return result;
}

// ─────────────────────────────────────────────────────────────────
// RECOMMENDATION SECTIONS
// Built from the already-scored array — zero extra DB calls.
// ─────────────────────────────────────────────────────────────────
function buildSections(
  projects: ScoredProject[],
  freelancer: FreelancerSnapshot,
) {
  const SECTION_SIZE = 6;
  const now = Date.now();
  const SIX_HOURS = 6 * 3_600_000;

  return {
    // Top-scored personalized projects
    recommended: projects.filter((p) => p.score >= 60).slice(0, SECTION_SIZE),

    // Posted in last 6 hours
    newProjects: projects
      .filter((p) => now - new Date(p.createdAt).getTime() < SIX_HOURS)
      .slice(0, SECTION_SIZE),

    // Under 5 proposals
    lowCompetition: [...projects]
      .filter((p) => p.proposalCount < 5)
      .sort((a, b) => a.proposalCount - b.proposalCount)
      .slice(0, SECTION_SIZE),

    // Top budget
    highBudget: [...projects]
      .sort((a, b) => b.budget - a.budget)
      .slice(0, SECTION_SIZE),

    // Same category as freelancer's saved/viewed projects
    similarToSaved: projects
      .filter((p) => freelancer.preferredCategories.includes(p.category?.slug))
      .slice(0, SECTION_SIZE),
  };
}

// ─────────────────────────────────────────────────────────────────
// CURSOR PAGINATION
// Takes the full cached response and slices by cursor.
// WHY cursor vs offset: Offset pagination breaks when new items are
// inserted between page loads — user sees duplicates or misses rows.
// ─────────────────────────────────────────────────────────────────
function paginateResponse(
  response: BrowseResponse,
  cursor?: string,
): BrowseResponse {
  const allProjects = response.projects;

  let startIndex = 0;
  if (cursor) {
    const idx = allProjects.findIndex((p) => p.id === cursor);
    startIndex = idx >= 0 ? idx + 1 : 0;
  }

  const page = allProjects.slice(startIndex, startIndex + PAGE_SIZE);
  const nextItem = allProjects[startIndex + PAGE_SIZE];

  return {
    ...response,
    projects: page,
    cursor: nextItem?.id,
    hasMore: !!nextItem,
  };
}

// ─────────────────────────────────────────────────────────────────
// CACHE KEY BUILDER
// ─────────────────────────────────────────────────────────────────
function buildCacheKey(
  freelancerId: string,
  filters: BrowseFilters,
  sort: SortOption,
): string {
  const filterHash = JSON.stringify(filters);
  return `browse:v1:${freelancerId}:${sort}:${Buffer.from(filterHash).toString("base64").slice(0, 20)}`;
}

// ── 11. Toggle Save Project ──────────────────────────────────
export async function toggleSaveProject(
  prisma: PrismaClient,
  freelancerId: string,
  projectId: string,
) {
  const freelancer = await prisma.freelancerProfile.findUnique({
    where: { userId: freelancerId },
    select: { id: true },
  });
  if (!freelancer) throw new Error("Freelancer not found");

  const existing = await prisma.savedProject.findUnique({
    where: {
      freelancerProfileId_projectId: {
        freelancerProfileId: freelancer.id,
        projectId,
      },
    },
  });

  if (existing) {
    await prisma.savedProject.delete({ where: { id: existing.id } });
    return { saved: false };
  } else {
    await prisma.savedProject.create({
      data: { freelancerProfileId: freelancer.id, projectId },
    });
    return { saved: true };
  }
}

// ── 12. Get Saved Projects ──────────────────────────────────
export async function getSavedProjects(
  prisma: PrismaClient,
  freelancerId: string,
) {
  const freelancer = await prisma.freelancerProfile.findUnique({
    where: { userId: freelancerId },
    select: { id: true },
  });
  if (!freelancer) throw new Error("Freelancer not found");

  const saved = await prisma.savedProject.findMany({
    where: { freelancerProfileId: freelancer.id },
    include: {
      project: {
        include: {
          category: true,
          skills: { include: { skill: true } },
          clientProfile: true,
        },
      },
    },
    orderBy: { savedAt: "desc" },
  });

  // Map to RawProject-like shape
  return saved.map((s) => ({
    ...s.project,
    isSaved: true,
    client: s.project.clientProfile
      ? {
          id: s.project.clientProfile.id,
          fullName: s.project.clientProfile.fullName,
          isVerified: false,
        }
      : { id: "", fullName: "Unknown", isVerified: false },
  }));
}

// ── 13. Record Project Interaction ──────────────────────────
export async function recordProjectInteraction(
  prisma: PrismaClient,
  freelancerId: string,
  projectId: string,
  type: InteractionType,
) {
  const freelancer = await prisma.freelancerProfile.findUnique({
    where: { userId: freelancerId },
    select: { id: true },
  });
  if (!freelancer) throw new Error("Freelancer not found");

  // Record it
  return await prisma.browseInteraction.create({
    data: {
      freelancerProfileId: freelancer.id,
      projectId,
      type: type as any,
    },
  });
}
