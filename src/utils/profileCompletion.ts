import { prisma } from "../config/prisma";

/**
 * Calculates profile completion using explicit per-field weights (total = 100%).
 *
 * Field Weights:
 *  - Full Name + Tagline  : 10%
 *  - Phone Number         :  5%
 *  - Country / Location   :  5%
 *  - Hourly Rate          : 10%
 *  - Bio (≥100 chars)     : 10%
 *  - Experience Level     :  5%
 *  - Skills (≥1)          : 15%
 *  - Languages (≥1)       :  5%
 *  - Education (≥1 entry) :  5%
 *  - Profile Image        : 10%
 *  - Preferred Budget     :  5%
 *  - Portfolio/Gig/Cert   : 10%
 *  - Any Social Link      :  5%
 *                   TOTAL : 100%
 */
export const updateProfileCompletion = async (
  userId: string
): Promise<number> => {
  const profile = (await prisma.freelancerProfile.findUnique({
    where: { userId },
    include: {
      skills: true,
      educations: true,
      certificates: true,
      gigs: true,
      user: true,
    } as any,
  })) as any;

  if (!profile || !profile.user) return 0;

  let score = 0;

  // 10% – Full Name + Tagline
  const name = profile.fullName || profile.user?.name || profile.user?.firstName;
  if (name?.trim()?.length >= 3 && profile.tagline?.trim()?.length >= 10) {
    score += 10;
  }

  // 5% – Phone Number
  if (profile.user?.phoneNumber?.trim()) {
    score += 5;
  }

  // 5% – Country / Location
  if (profile.location?.trim()) {
    score += 5;
  }

  // 10% – Hourly Rate
  if (profile.hourlyRate && Number(profile.hourlyRate) >= 5) {
    score += 10;
  }

  // 10% – Bio (≥100 chars)
  if (profile.bio?.trim()?.length >= 100) {
    score += 10;
  }

  // 5% – Experience Level
  if (profile.experienceLevel) {
    score += 5;
  }

  // 15% – Skills (at least 1)
  if (Array.isArray(profile.skills) && profile.skills.length > 0) {
    score += 15;
  }

  // 5% – Languages (at least 1)
  if (Array.isArray(profile.languages) && profile.languages.length > 0) {
    score += 5;
  }

  // 5% – Education (at least 1 entry with school + degree)
  const hasEducation =
    Array.isArray(profile.educations) &&
    profile.educations.some(
      (e: any) => e.school?.trim() && e.degree?.trim()
    );
  if (hasEducation) {
    score += 5;
  }

  // 10% – Profile Image (from any source: Google, manual upload, etc.)
  if (profile.user?.profileImage?.trim()) {
    score += 10;
  }

  // 5% – Preferred Budget Range
  if (
    profile.preferredBudgetMin != null &&
    profile.preferredBudgetMax != null &&
    profile.preferredBudgetMax > 0
  ) {
    score += 5;
  }

  // 10% – Portfolio proof (any cert OR gig)
  const hasCertsOrGigs =
    (Array.isArray(profile.certificates) && profile.certificates.length > 0) ||
    (Array.isArray(profile.gigs) && profile.gigs.length > 0);
  if (hasCertsOrGigs) {
    score += 10;
  }

  // 5% – Any social / professional link
  const hasLink = !!(
    profile.github?.trim() ||
    profile.linkedin?.trim() ||
    profile.portfolio?.trim() ||
    profile.website?.trim()
  );
  if (hasLink) {
    score += 5;
  }

  // Hard-cap at 100
  const finalScore = Math.min(score, 100);

  // Save back to DB
  await prisma.freelancerProfile.update({
    where: { userId },
    data: {
      profileCompletion: finalScore,
      profileCompletionScore: finalScore,
    },
  });

  return finalScore;
};
