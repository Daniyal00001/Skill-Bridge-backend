import { prisma } from '../config/prisma'

/**
 * Calculates profile completion mathematically using:
 * percentage = (filled data fields * 100) / total data fields
 */
export const updateProfileCompletion = async (userId: string): Promise<number> => {
  const profile = await prisma.freelancerProfile.findUnique({
    where: { userId },
    include: {
      skills: true,
      educations: true,
      user: true,
    }
  })

  if (!profile || !profile.user) return 0

  // Map out every single required data point across the onboarding flow
  const requiredFields = [
    // Step 1: Personal Info
    !!profile.user.firstName?.trim(),
    !!profile.user.lastName?.trim(),
    !!profile.location?.trim(),
    !!profile.tagline?.trim(),

    // Step 2: Professional Details
    !!profile.hourlyRate,
    !!profile.bio?.trim(),
    !!profile.experienceLevel,
    !!profile.availability,

    // Step 3: Skills & Education
    Array.isArray(profile.skills) && profile.skills.length > 0,
    Array.isArray(profile.educations) && profile.educations.length > 0 && !!profile.educations[0].school?.trim(),
    Array.isArray(profile.educations) && profile.educations.length > 0 && !!profile.educations[0].degree?.trim(),
    Array.isArray(profile.educations) && profile.educations.length > 0 && !!profile.educations[0].year?.trim(),

    // Step 4: Verification & Identity Files (Cloudinary URLs)
    !!profile.user.profileImage?.trim(),
    !!profile.user.idDocumentUrl?.trim() || profile.user.isIdVerified,

    // Step 5: Links (Require at least one professional link)
    !!(profile.github?.trim() || profile.linkedin?.trim() || profile.portfolio?.trim() || profile.website?.trim())
  ]

  const totalFields = requiredFields.length
  const filledFields = requiredFields.filter(Boolean).length

  // Math: (filled * 100) / total
  const finalScore = Math.round((filledFields * 100) / totalFields)

  // Save back to DB
  await prisma.freelancerProfile.update({
    where: { userId },
    data: { profileCompletion: finalScore }
  })

  return finalScore
}
