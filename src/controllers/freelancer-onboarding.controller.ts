import { Request, Response } from 'express'
import { prisma } from '../config/prisma'
import { uploadToCloudinary } from '../utils/uploadToCloudinary'
import { ExperienceLevel, AvailabilityStatus } from '@prisma/client'

// Get Current User Profile
export const getMyFreelancerProfile = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    if (!userId) return res.status(401).json({ success: false, message: 'Unauthorized' })

    const profile = await prisma.freelancerProfile.findUnique({
      where: { userId },
      include: {
        skills: { include: { skill: true } },
        portfolioItems: true,
        certificates: true,
        educations: true,
        user: { select: { email: true, firstName: true, lastName: true, profileImage: true, isEmailVerified: true, isIdVerified: true } }
      }
    })

    if (!profile) return res.status(404).json({ success: false, message: 'Profile not found' })
    return res.status(200).json({ success: true, data: profile })
  } catch (error) {
    console.error('Get My Profile error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error' })
  }
}

// Step 1: Personal Info
export const updateOnboardingStep1 = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { firstName, lastName, location, preferredClientLocation, tagline } = req.body

    if (!userId) return res.status(401).json({ success: false, message: 'Unauthorized' })

    // Update User model (name)
    const user = await prisma.user.update({
      where: { id: userId },
      data: {
        firstName,
        lastName,
        name: `${firstName} ${lastName}`.trim()
      }
    })

    // Update Freelancer Profile
    const profile = await prisma.freelancerProfile.update({
      where: { userId },
      data: {
        location,
        preferredClientLocation,
        tagline,
        fullName: `${firstName} ${lastName}`.trim(),
        profileCompletion: { increment: 20 }
      }
    })

    return res.status(200).json({ success: true, data: profile })
  } catch (error) {
    console.error('Update Step 1 error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error' })
  }
}

// Step 2: Professional Details
export const updateOnboardingStep2 = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { hourlyRate, bio, availability, experienceLevel } = req.body

    const profile = await prisma.freelancerProfile.update({
      where: { userId },
      data: {
        hourlyRate: parseFloat(hourlyRate),
        bio,
        availability: availability as AvailabilityStatus,
        experienceLevel: experienceLevel as ExperienceLevel,
        profileCompletion: { increment: 20 }
      }
    })

    return res.status(200).json({ success: true, data: profile })
  } catch (error) {
    console.error('Update Step 2 error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error' })
  }
}

// Step 3: Skills, Education & Certifications
export const updateOnboardingStep3 = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { skills, education, certifications } = req.body

    const profile = await prisma.freelancerProfile.findUnique({ where: { userId }})
    if (!profile) return res.status(404).json({ success: false, message: 'Profile not found' })

    // Insert Education
    if (education && Array.isArray(education) && education.length > 0) {
       // Clear old records first
       await prisma.education.deleteMany({ where: { freelancerProfileId: profile.id } })
       
       await prisma.education.createMany({
         data: education.map((edu: any) => ({
           freelancerProfileId: profile.id,
           school: edu.school,
           degree: edu.degree,
           year: edu.year
         }))
       })
    }

    // Skills
    if (skills && Array.isArray(skills)) {
      // Clear old records first
      await prisma.freelancerSkill.deleteMany({ where: { freelancerProfileId: profile.id } })

      for (const sk of skills) {
        // Find or create global skill
        const skillObj = await prisma.skill.upsert({
          where: { name: sk.name },
          update: {},
          create: { name: sk.name, category: "General" }
        })
        await prisma.freelancerSkill.upsert({
          where: { freelancerProfileId_skillId: { freelancerProfileId: profile.id, skillId: skillObj.id } },
          update: { proficiencyLevel: sk.level || 3 },
          create: { freelancerProfileId: profile.id, skillId: skillObj.id, proficiencyLevel: sk.level || 3 }
        })
      }
    }

    // Add Certs
    if (certifications && Array.isArray(certifications) && certifications.length > 0) {
       // Clear old records first
       await prisma.certificate.deleteMany({ where: { freelancerProfileId: profile.id } })

       await prisma.certificate.createMany({
         data: certifications.map((c: any) => ({
           freelancerProfileId: profile.id,
           title: c.title,
           issuingOrganization: c.issuingOrganization,
           issueDate: new Date(c.issueDate),
           expiryDate: c.expiryDate ? new Date(c.expiryDate) : undefined,
           credentialUrl: c.credentialUrl
         }))
       })
    }

    await prisma.freelancerProfile.update({
      where: { userId },
      data: { profileCompletion: { increment: 20 } }
    })

    return res.status(200).json({ success: true, message: 'Step 3 completed' })
  } catch (error) {
    console.error('Update Step 3 error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error' })
  }
}

// Upload endpoint (multipart/form-data)
export const uploadOnboardingFiles = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    
    // Express Multer format
    const files = req.files as { [fieldname: string]: Express.Multer.File[] } | undefined
    
    if (!files) {
      return res.status(400).json({ success: false, message: 'No files provided' })
    }

    const updates: any = {}
    
    // Upload ID
    if (files['idDocument'] && files['idDocument'][0]) {
      const idUrl = await uploadToCloudinary(files['idDocument'][0].buffer)
      await prisma.user.update({
        where: { id: userId },
        data: { idDocumentUrl: idUrl, isIdVerified: true } // Mock verified immediately
      })
      updates.idDocumentUrl = idUrl
    }

    // Profile Pic
    if (files['profileImage'] && files['profileImage'][0]) {
      const picUrl = await uploadToCloudinary(files['profileImage'][0].buffer)
      await prisma.user.update({
        where: { id: userId },
        data: { profileImage: picUrl }
      })
      updates.profileImage = picUrl
    }

    // Increment completion
    const profile = await prisma.freelancerProfile.update({
      where: { userId },
      data: { profileCompletion: { increment: 20 } }
    })

    return res.status(200).json({ success: true, data: { ...updates, profileCompletion: profile.profileCompletion } })
  } catch (error) {
    console.error('Upload files error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error' })
  }
}

// Step 5: Links
export const updateOnboardingStep5 = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { github, linkedin, portfolio, website } = req.body

    const profile = await prisma.freelancerProfile.update({
      where: { userId },
      data: {
        github,
        linkedin,
        portfolio,
        website,
        profileCompletion: 100 // Final step
      }
    })

    return res.status(200).json({ success: true, data: profile })
  } catch (error) {
    console.error('Update Step 5 error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error' })
  }
}
