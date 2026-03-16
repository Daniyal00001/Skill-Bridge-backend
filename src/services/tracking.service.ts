/**
 * tracking.service.ts
 * location: backend/src/services/tracking.service.ts
 * ─────────────────────────────────────────────────────────────────
 * WHY THIS EXISTS:
 *   Browse system ko personalize karne ke liye humein pata hona
 *   chahiye freelancer kya dekh raha hai, save kar raha hai, apply
 *   kar raha hai. Yeh service woh sab events record karti hai.
 *
 * WHY SEPARATE SERVICE (not inside browse.service.ts):
 *   Tracking = cross-cutting concern. Kal ko notifications,
 *   analytics dashboard, ya ML pipeline bhi yahi data use karega.
 *   Ek jagah rakho, sab use karein.
 *
 * DESIGN PRINCIPLE — "Fire and Forget":
 *   Tracking events non-blocking hain. Agar DB write fail ho,
 *   user ko pata nahi chalna chahiye. Isliye await nahi karte
 *   calling code mein — bas trackEvent() call karo aur aage bado.
 * ─────────────────────────────────────────────────────────────────
 */

import { PrismaClient, InteractionType } from "@prisma/client";
import { invalidateBrowseCache } from "../modules/browse/browse.cache";

// ─────────────────────────────────────────────────────────────────
// CORE TRACK FUNCTION
// Sab events yahan se guzarte hain.
// ─────────────────────────────────────────────────────────────────
export async function trackInteraction(
  prisma: PrismaClient,
  params: {
    freelancerProfileId: string;
    type: InteractionType;
    projectId?: string;
    categorySlug?: string;
    metadata?: Record<string, any>;
  }
): Promise<void> {
  try {
    await prisma.browseInteraction.create({
      data: {
        freelancerProfileId: params.freelancerProfileId,
        type: params.type,
        projectId: params.projectId ?? null,
        categorySlug: params.categorySlug ?? null,
        metadata: params.metadata ?? undefined,
      },
    });
  } catch (err) {
    // Non-fatal — tracking failure should NEVER break user flow
    console.error("[Tracking] Failed to record interaction:", err);
  }
}

// ─────────────────────────────────────────────────────────────────
// SPECIFIC EVENT HELPERS
// Controllers call these — not trackInteraction directly.
// WHY named helpers: Type-safe, readable, no raw string mistakes.
// ─────────────────────────────────────────────────────────────────

/**
 * Called when freelancer opens a project detail page.
 * Also increments project viewCount in same call (two birds, one stone).
 */
export async function trackProjectView(
  prisma: PrismaClient,
  freelancerProfileId: string,
  projectId: string,
  categorySlug?: string
): Promise<void> {
  // Run both writes in parallel — faster than sequential awaits
  await Promise.allSettled([
    trackInteraction(prisma, {
      freelancerProfileId,
      type: InteractionType.VIEW,
      projectId,
      categorySlug,
    }),
    // Increment project view counter
    prisma.project.update({
      where: { id: projectId },
      data: { viewCount: { increment: 1 } },
    }),
  ]);
}

/**
 * Called when freelancer saves/bookmarks a project.
 * Creates SavedProject record + tracks interaction.
 * Returns { saved: true } or { saved: false } (already saved).
 */
export async function trackProjectSave(
  prisma: PrismaClient,
  freelancerProfileId: string,
  projectId: string,
  categorySlug?: string
): Promise<{ saved: boolean; alreadySaved: boolean }> {
  try {
    // Check if already saved
    const existing = await prisma.savedProject.findUnique({
      where: {
        freelancerProfileId_projectId: { freelancerProfileId, projectId },
      },
    });

    if (existing) {
      return { saved: false, alreadySaved: true };
    }

    // Create saved record + track interaction in parallel
    await Promise.all([
      prisma.savedProject.create({
        data: { freelancerProfileId, projectId },
      }),
      trackInteraction(prisma, {
        freelancerProfileId,
        type: InteractionType.SAVE,
        projectId,
        categorySlug,
      }),
    ]);

    return { saved: true, alreadySaved: false };
  } catch (err) {
    console.error("[Tracking] Save failed:", err);
    return { saved: false, alreadySaved: false };
  }
}

/**
 * Called when freelancer un-saves a project.
 */
export async function trackProjectUnsave(
  prisma: PrismaClient,
  freelancerProfileId: string,
  projectId: string
): Promise<void> {
  await Promise.allSettled([
    prisma.savedProject.deleteMany({
      where: { freelancerProfileId, projectId },
    }),
    trackInteraction(prisma, {
      freelancerProfileId,
      type: InteractionType.UNSAVE,
      projectId,
    }),
  ]);
}

/**
 * Called when a proposal is successfully submitted.
 * WHY track apply separately from Proposal creation:
 *   Proposal creation is in proposal.controller.ts (existing code).
 *   We don't want to touch that controller — just call this after.
 *   Also updates preferredBudget signals from proposal amount.
 */
export async function trackProjectApply(
  prisma: PrismaClient,
  freelancerProfileId: string,
  projectId: string,
  proposedPrice: number,
  categorySlug?: string
): Promise<void> {
  await Promise.allSettled([
    trackInteraction(prisma, {
      freelancerProfileId,
      type: InteractionType.APPLY,
      projectId,
      categorySlug,
      metadata: { proposedPrice },
    }),
    // Update preferred budget range from proposal history
    // WHY: If a freelancer keeps bidding at $500–$1500, we learn that range
    updatePreferredBudgetSignal(prisma, freelancerProfileId, proposedPrice),
    // Invalidate this freelancer's browse cache so applied project disappears
    invalidateBrowseCache(freelancerProfileId),
  ]);
}

/**
 * Called when freelancer clicks a category filter chip.
 * Builds category preference signal over time.
 */
export async function trackCategoryClick(
  prisma: PrismaClient,
  freelancerProfileId: string,
  categorySlug: string
): Promise<void> {
  await trackInteraction(prisma, {
    freelancerProfileId,
    type: InteractionType.CATEGORY_CLICK,
    categorySlug,
  });
}

// ─────────────────────────────────────────────────────────────────
// BUDGET SIGNAL UPDATER
// After each proposal, update freelancer's preferred budget range.
//
// WHY rolling average (not just last value):
//   Single proposal might be outlier. Rolling average of last 10
//   proposals gives stable signal without overreacting to one bid.
// ─────────────────────────────────────────────────────────────────
async function updatePreferredBudgetSignal(
  prisma: PrismaClient,
  freelancerProfileId: string,
  newProposedPrice: number
): Promise<void> {
  try {
    // Get last 10 proposals to compute rolling range
    const recentProposals = await prisma.proposal.findMany({
      where: { freelancerProfileId },
      orderBy: { submittedAt: "desc" },
      take: 10,
      select: { proposedPrice: true },
    });

    const prices = recentProposals.map((p) => p.proposedPrice);
    prices.push(newProposedPrice); // include current

    const min = Math.min(...prices);
    const max = Math.max(...prices);

    // Give a 20% buffer so near-range projects also match
    await prisma.freelancerProfile.update({
      where: { id: freelancerProfileId },
      data: {
        preferredBudgetMin: min * 0.8,
        preferredBudgetMax: max * 1.2,
      },
    });
  } catch (err) {
    console.error("[Tracking] Budget signal update failed:", err);
  }
}

// ─────────────────────────────────────────────────────────────────
// LOGIN TRACKER
// Call this from your auth controller after successful login.
// Updates lastLoginAt for activity scoring.
// ─────────────────────────────────────────────────────────────────
export async function trackFreelancerLogin(
  prisma: PrismaClient,
  freelancerProfileId: string
): Promise<void> {
  try {
    await prisma.freelancerProfile.update({
      where: { id: freelancerProfileId },
      data: { lastLoginAt: new Date() },
    });
  } catch (err) {
    console.error("[Tracking] Login timestamp update failed:", err);
  }
}

// ─────────────────────────────────────────────────────────────────
// DISPUTE RATIO UPDATER
// Call this from dispute resolution (admin controller).
// WHY here: Keeps dispute logic centralized in tracking service,
// admin controller bas "dispute resolved" signal bhejta hai.
// ─────────────────────────────────────────────────────────────────
export async function updateDisputeRatio(
  prisma: PrismaClient,
  freelancerProfileId: string
): Promise<void> {
  try {
    // Count total completed contracts
    const totalContracts = await prisma.contract.count({
      where: {
        freelancerProfileId,
        status: { in: ["COMPLETED", "DISPUTED"] },
      },
    });

    if (totalContracts === 0) return;

    // Count disputed contracts involving this freelancer
    const disputedContracts = await prisma.contract.count({
      where: {
        freelancerProfileId,
        status: "DISPUTED",
      },
    });

    const ratio = disputedContracts / totalContracts;

    await prisma.freelancerProfile.update({
      where: { id: freelancerProfileId },
      data: { disputeRatio: ratio },
    });
  } catch (err) {
    console.error("[Tracking] Dispute ratio update failed:", err);
  }
}

// ─────────────────────────────────────────────────────────────────
// CLIENT STATS UPDATER
// Call this after a proposal is accepted (contract created).
// Updates client hireRate and totalHires for client trust scoring.
// ─────────────────────────────────────────────────────────────────
export async function updateClientStats(
  prisma: PrismaClient,
  clientProfileId: string
): Promise<void> {
  try {
    const [totalProjects, totalHires] = await Promise.all([
      prisma.project.count({ where: { clientProfileId } }),
      prisma.contract.count({
        where: { project: { clientProfileId } },
      }),
    ]);

    const hireRate =
      totalProjects > 0 ? totalHires / totalProjects : 0;

    await prisma.clientProfile.update({
      where: { id: clientProfileId },
      data: {
        totalHires,
        hireRate,
      },
    });
  } catch (err) {
    console.error("[Tracking] Client stats update failed:", err);
  }
}

// ─────────────────────────────────────────────────────────────────
// CLIENT RATING UPDATER
// Call this after a review is submitted (review.controller.ts).
// ─────────────────────────────────────────────────────────────────
export async function updateClientAverageRating(
  prisma: PrismaClient,
  clientUserId: string
): Promise<void> {
  try {
    const reviews = await prisma.review.findMany({
      where: { receiverId: clientUserId },
      select: { rating: true },
    });

    if (reviews.length === 0) return;

    const avg =
      reviews.reduce((sum, r) => sum + r.rating, 0) / reviews.length;

    // Update through user → clientProfile relation
    await prisma.clientProfile.updateMany({
      where: { userId: clientUserId },
      data: { averageRating: avg },
    });
  } catch (err) {
    console.error("[Tracking] Client rating update failed:", err);
  }
}