import { Request, Response } from "express";
import { prisma } from "../config/prisma";
import { uploadToCloudinary, deleteFromCloudinary } from "../utils/uploadToCloudinary";
import { updateProfileCompletion } from "../utils/profileCompletion";
import { ExperienceLevel, AvailabilityStatus } from "@prisma/client";

// Get Current User Profile
export const getMyFreelancerProfile = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId;
    if (!userId)
      return res.status(401).json({ success: false, message: "Unauthorized" });

    const profile = await prisma.freelancerProfile.findUnique({
      where: { userId },
      include: {
        skills: { include: { skill: true } },
        portfolioItems: true,
        certificates: true,
        gigs: true,
        educations: true,
        user: {
          select: {
            email: true,
            firstName: true,
            lastName: true,
            profileImage: true,
            isEmailVerified: true,
            isIdVerified: true,
          },
        },
      },
    });

    if (!profile)
      return res
        .status(404)
        .json({ success: false, message: "Profile not found" });
    return res.status(200).json({ success: true, data: profile });
  } catch (error) {
    console.error("Get My Profile error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};

// Step 1: Personal Info
export const updateOnboardingStep1 = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId;
    const { firstName, lastName, phoneNumber, location, region, tagline } =
      req.body;

    if (!userId)
      return res.status(401).json({ success: false, message: "Unauthorized" });

    if (!firstName || firstName.length < 2) return res.status(400).json({ success: false, message: "First name must be at least 2 characters." });
    if (!lastName || lastName.length < 2) return res.status(400).json({ success: false, message: "Last name must be at least 2 characters." });
    if (!tagline || tagline.length < 10) return res.status(400).json({ success: false, message: "Tagline must be at least 10 characters." });
    if (!phoneNumber || !/^\+?[1-9]\d{1,14}$/.test(phoneNumber.replace(/\s/g, ""))) {
      return res.status(400).json({ success: false, message: "Invalid phone number format. Must start with '+'." });
    }
    if (!location) return res.status(400).json({ success: false, message: "Country is required." });

    // Update User model (name)
    const user = await prisma.user.update({
      where: { id: userId },
      data: {
        firstName,
        lastName,
        phoneNumber,
        name: `${firstName} ${lastName}`.trim(),
      },
    });

    // Update Freelancer Profile
    const profile = await prisma.freelancerProfile.update({
      where: { userId },
      data: {
        location,
        region,
        tagline,
        fullName: `${firstName} ${lastName}`.trim(),
      },
    });

    const newCompletion = await updateProfileCompletion(userId);
    return res
      .status(200)
      .json({
        success: true,
        data: { ...profile, profileCompletion: newCompletion },
      });
  } catch (error: any) {
    console.error("Update Step 1 error:", error);
    if (error.code === 'P2002') return res.status(400).json({ success: false, message: "This phone number is already registered." });
    return res.status(500).json({ success: false, message: error.message || "Internal server error" });
  }
};

// Step 2: Professional Details
export const updateOnboardingStep2 = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId;
    const { hourlyRate, bio, availability, experienceLevel } = req.body;

    if (!userId) return res.status(401).json({ success: false, message: "Unauthorized" });
    if (!hourlyRate || Number(hourlyRate) < 5) return res.status(400).json({ success: false, message: "Minimum hourly rate is $5." });
    if (!bio || bio.length < 100) return res.status(400).json({ success: false, message: "Bio must be at least 100 characters." });

    const profile = await prisma.freelancerProfile.update({
      where: { userId },
      data: {
        hourlyRate: parseFloat(hourlyRate),
        bio,
        availability: availability as AvailabilityStatus,
        experienceLevel: experienceLevel as ExperienceLevel,
      },
    });

    const newCompletion = await updateProfileCompletion(userId);
    return res
      .status(200)
      .json({
        success: true,
        data: { ...profile, profileCompletion: newCompletion },
      });
  } catch (error) {
    console.error("Update Step 2 error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};

// Step 3: Skills, Education & Certifications
export const updateOnboardingStep3 = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId;
    const { skills, education, certifications, languages, gigs } = req.body;

    if (!userId) return res.status(401).json({ success: false, message: "Unauthorized" });
    if (!skills || !Array.isArray(skills) || skills.length === 0) {
      return res.status(400).json({ success: false, message: "At least one skill is required." });
    }

    const profile = await prisma.freelancerProfile.findUnique({
      where: { userId },
    });
    if (!profile)
      return res
        .status(404)
        .json({ success: false, message: "Profile not found" });

    // Insert Education
    if (education && Array.isArray(education)) {
      // Clear old records first
      await prisma.education.deleteMany({
        where: { freelancerProfileId: profile.id },
      });

      if (education.length > 0) {
        await prisma.education.createMany({
          data: education.map((edu: any) => ({
            freelancerProfileId: profile.id,
            school: edu.school,
            degree: edu.degree,
            year: edu.year,
          })),
        });
      }
    }

    // Skills
    if (skills && Array.isArray(skills)) {
      // Clear old records first
      await prisma.freelancerSkill.deleteMany({
        where: { freelancerProfileId: profile.id },
      });

      for (const sk of skills) {
        // Find or create global skill
        const skillObj = await prisma.skill.upsert({
          where: { name: sk.name },
          update: {},
          create: { name: sk.name, category: "General" },
        });
        await prisma.freelancerSkill.upsert({
          where: {
            freelancerProfileId_skillId: {
              freelancerProfileId: profile.id,
              skillId: skillObj.id,
            },
          },
          update: { proficiencyLevel: sk.level || 3 },
          create: {
            freelancerProfileId: profile.id,
            skillId: skillObj.id,
            proficiencyLevel: sk.level || 3,
          },
        });
      }
    }

    // Add Certs
    if (certifications && Array.isArray(certifications)) {
      // Clear old records & assets first
      const oldCerts = await prisma.certificate.findMany({
        where: { freelancerProfileId: profile.id },
      });
      for (const c of oldCerts) {
        if (c.credentialUrl) await deleteFromCloudinary(c.credentialUrl);
      }
      
      await prisma.certificate.deleteMany({
        where: { freelancerProfileId: profile.id },
      });

      if (certifications.length > 0) {
        await prisma.certificate.createMany({
          data: certifications.map((c: any) => ({
            freelancerProfileId: profile.id,
            title: c.title,
            issuingOrganization: c.issuingOrganization,
            issueDate: new Date(c.issueDate),
            expiryDate: c.expiryDate ? new Date(c.expiryDate) : undefined,
            credentialUrl: c.credentialUrl,
          })),
        });
      }
    }

    // Languages
    if (languages && Array.isArray(languages)) {
      await prisma.freelancerProfile.update({
        where: { id: profile.id },
        data: { languages },
      });
    }

    // Gigs
    if (gigs && Array.isArray(gigs)) {
      // Clear old records & assets first
      const oldGigs = await prisma.gig.findMany({
        where: { freelancerProfileId: profile.id },
      });
      for (const g of oldGigs) {
        if (g.fileUrl) await deleteFromCloudinary(g.fileUrl);
      }

      await prisma.gig.deleteMany({
        where: { freelancerProfileId: profile.id },
      });
      if (gigs.length > 0) {
        await prisma.gig.createMany({
          data: gigs.map((g: any) => ({
            freelancerProfileId: profile.id,
            title: g.title,
            description: g.description,
            fileUrl: g.fileUrl,
          })),
        });
      }
    }

    await updateProfileCompletion(userId);
    return res.status(200).json({ success: true, message: "Step 3 completed" });
  } catch (error) {
    console.error("Update Step 3 error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};

// Upload endpoint (multipart/form-data)
export const uploadOnboardingFiles = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId;

    // Express Multer format
    const files = req.files as
      | { [fieldname: string]: Express.Multer.File[] }
      | undefined;

    if (!files) {
      return res
        .status(400)
        .json({ success: false, message: "No files provided" });
    }

    const profile = await prisma.freelancerProfile.findUnique({
      where: { userId },
      include: { 
        certificates: true, 
        gigs: true,
        user: { select: { profileImage: true, idDocumentUrl: true } }
      },
    });
    if (!profile)
      return res.status(404).json({ success: false, message: "Profile not found" });

    // Validate Limit
    const newCerts = files["certFiles"] ? files["certFiles"].length : 0;
    const newGigs = files["gigFiles"] ? files["gigFiles"].length : 0;

    if (profile.certificates.length + newCerts > 4) {
      return res
        .status(400)
        .json({
          success: false,
          message: `Total certificates would exceed limit of 4. Already have ${profile.certificates.length}.`,
        });
    }

    if (profile.gigs.length + newGigs > 4) {
      return res
        .status(400)
        .json({
          success: false,
          message: `Total gigs would exceed limit of 4. Already have ${profile.gigs.length}.`,
        });
    }

    const updates: any = {};

    // Upload ID
    if (files["idDocument"] && files["idDocument"][0]) {
      // Delete old one if exists
      if (profile.user.idDocumentUrl) {
        await deleteFromCloudinary(profile.user.idDocumentUrl);
      }
      
      const idUrl = await uploadToCloudinary(files["idDocument"][0].buffer);
      await prisma.user.update({
        where: { id: userId },
        data: { idDocumentUrl: idUrl, isIdVerified: true }, // Mock verified immediately
      });
      updates.idDocumentUrl = idUrl;
    }

    // Profile Pic
    if (files["profileImage"] && files["profileImage"][0]) {
      // Delete old one if exists
      if (profile.user.profileImage) {
        await deleteFromCloudinary(profile.user.profileImage);
      }

      const picUrl = await uploadToCloudinary(files["profileImage"][0].buffer);
      await prisma.user.update({
        where: { id: userId },
        data: { profileImage: picUrl },
      });
      updates.profileImage = picUrl;
    }

    // Certs
    if (files["certFiles"]) {
      const certTitles = req.body.certTitles ? (Array.isArray(req.body.certTitles) ? req.body.certTitles : req.body.certTitles.split(',')) : [];
      for (let i = 0; i < files["certFiles"].length; i++) {
        const url = await uploadToCloudinary(files["certFiles"][i].buffer);
        await prisma.certificate.create({
          data: {
            freelancerProfileId: profile.id,
            title: certTitles[i] || `Certificate ${i + 1}`,
            issuingOrganization: 'Uploaded',
            issueDate: new Date(),
            credentialUrl: url
          }
        });
      }
    }

    // Gigs
    if (files["gigFiles"]) {
      const gigTitles = req.body.gigTitles ? (Array.isArray(req.body.gigTitles) ? req.body.gigTitles : req.body.gigTitles.split(',')) : [];
      for (let i = 0; i < files["gigFiles"].length; i++) {
        const url = await uploadToCloudinary(files["gigFiles"][i].buffer);
        await prisma.gig.create({
          data: {
            freelancerProfileId: profile.id,
            title: gigTitles[i] || `Gig ${i + 1}`,
            fileUrl: url
          }
        });
      }
    }

    // Increment completion
    const newCompletion = await updateProfileCompletion(userId);

    return res
      .status(200)
      .json({
        success: true,
        data: { ...updates, profileCompletion: newCompletion },
      });
  } catch (error) {
    console.error("Upload files error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};

// Step 5: Links
export const updateOnboardingStep5 = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId;
    const { github, linkedin, portfolio, website, preferredCategories } = req.body;

    if (preferredCategories && Array.isArray(preferredCategories) && preferredCategories.length > 4) {
      return res.status(400).json({ success: false, message: "You can select a maximum of 4 preferred categories." });
    }

    const profile = await prisma.freelancerProfile.update({
      where: { userId },
      data: {
        github,
        linkedin,
        portfolio,
        website,
        preferredCategories,
      },
    });

    const newCompletion = await updateProfileCompletion(userId);
    return res
      .status(200)
      .json({
        success: true,
        data: { ...profile, profileCompletion: newCompletion },
      });
  } catch (error) {
    console.error("Update Step 5 error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};

// Edit Profile (Phase 5)
export const updateFreelancerProfile = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId;
    if (!userId)
      return res.status(401).json({ success: false, message: "Unauthorized" });

    const {
      firstName,
      lastName,
      location,
      preferredClientLocation,
      tagline,
      bio,
      hourlyRate,
      experienceLevel,
      availability,
      github,
      linkedin,
      portfolio,
      website,
      preferredCategories,
      skills,
      education,
      certifications,
      languages,
      gigs,
      idDocumentUrl,
      profileImage,
      region,
    } = req.body;

    if (preferredCategories && Array.isArray(preferredCategories) && preferredCategories.length > 4) {
      return res.status(400).json({ success: false, message: "You can select a maximum of 4 preferred categories." });
    }

    const profile = await prisma.freelancerProfile.findUnique({
      where: { userId },
    });
    if (!profile)
      return res
        .status(404)
        .json({ success: false, message: "Profile not found" });

    // User level updates
    const userUpdateData: any = {};
    if (firstName !== undefined) userUpdateData.firstName = firstName;
    if (lastName !== undefined) userUpdateData.lastName = lastName;
    if (firstName !== undefined && lastName !== undefined) {
      userUpdateData.name = `${firstName} ${lastName}`.trim();
    }
    // Handle File removal (if explicitly passed as empty string or null to delete)
    if (idDocumentUrl === null || idDocumentUrl === "") {
      userUpdateData.idDocumentUrl = null;
      userUpdateData.isIdVerified = false;
    }
    if (profileImage === null || profileImage === "") {
      userUpdateData.profileImage = null;
    }

    if (Object.keys(userUpdateData).length > 0) {
      await prisma.user.update({
        where: { id: userId },
        data: userUpdateData,
      });
    }

    // Profile level updates
    const profileUpdateData: any = {};
    if (location !== undefined) profileUpdateData.location = location;
    if (region !== undefined) profileUpdateData.region = region;
    if (tagline !== undefined) profileUpdateData.tagline = tagline;
    if (bio !== undefined) profileUpdateData.bio = bio;
    if (hourlyRate !== undefined)
      profileUpdateData.hourlyRate = Number(hourlyRate);
    if (experienceLevel !== undefined)
      profileUpdateData.experienceLevel = experienceLevel;
    if (availability !== undefined)
      profileUpdateData.availability = availability;
    if (github !== undefined) profileUpdateData.github = github;
    if (linkedin !== undefined) profileUpdateData.linkedin = linkedin;
    if (portfolio !== undefined) profileUpdateData.portfolio = portfolio;
    if (website !== undefined) profileUpdateData.website = website;
    if (languages !== undefined) profileUpdateData.languages = languages;
    if (preferredCategories !== undefined)
      profileUpdateData.preferredCategories = preferredCategories;
    if (firstName !== undefined && lastName !== undefined) {
      profileUpdateData.fullName = `${firstName} ${lastName}`.trim();
    }

    if (Object.keys(profileUpdateData).length > 0) {
      await prisma.freelancerProfile.update({
        where: { id: profile.id },
        data: profileUpdateData,
      });
    }

    // Skills
    if (skills && Array.isArray(skills)) {
      await prisma.freelancerSkill.deleteMany({
        where: { freelancerProfileId: profile.id },
      });
      for (const sk of skills) {
        const skillName = sk.name || sk;
        const skillObj = await prisma.skill.upsert({
          where: { name: skillName },
          update: {},
          create: { name: skillName, category: "General" },
        });
        await prisma.freelancerSkill.upsert({
          where: {
            freelancerProfileId_skillId: {
              freelancerProfileId: profile.id,
              skillId: skillObj.id,
            },
          },
          update: { proficiencyLevel: sk.level || 3 },
          create: {
            freelancerProfileId: profile.id,
            skillId: skillObj.id,
            proficiencyLevel: sk.level || 3,
          },
        });
      }
    }

    // Education
    if (education && Array.isArray(education)) {
      await prisma.education.deleteMany({
        where: { freelancerProfileId: profile.id },
      });
      if (education.length > 0) {
        await prisma.education.createMany({
          data: education.map((edu: any) => ({
            freelancerProfileId: profile.id,
            school: edu.school,
            degree: edu.degree,
            year: edu.year,
          })),
        });
      }
    }

    // Gigs
    if (gigs && Array.isArray(gigs)) {
      // Clean up old gigs first
      const oldGigs = await prisma.gig.findMany({
        where: { freelancerProfileId: profile.id },
      });
      for (const g of oldGigs) {
        if (g.fileUrl) await deleteFromCloudinary(g.fileUrl);
      }

      await prisma.gig.deleteMany({
        where: { freelancerProfileId: profile.id },
      });
      if (gigs.length > 0) {
        await prisma.gig.createMany({
          data: gigs.map((g: any) => ({
            freelancerProfileId: profile.id,
            title: g.title || g,
            description: g.description,
            fileUrl: g.fileUrl,
          })),
        });
      }
    }

    const updatedProfile = await prisma.freelancerProfile.findUnique({
      where: { userId },
      include: {
        skills: { include: { skill: true } },
        portfolioItems: true,
        certificates: true,
        educations: true,
        gigs: true,
        user: {
          select: {
            email: true,
            firstName: true,
            lastName: true,
            profileImage: true,
            isEmailVerified: true,
            isIdVerified: true,
          },
        },
      } as any,
    });

    await updateProfileCompletion(userId);

    // fetch again or just send back updatedProfile + profileCompletion
    updatedProfile!.profileCompletion = await updateProfileCompletion(userId);

    return res.status(200).json({ success: true, data: updatedProfile });
  } catch (error) {
    console.error("Update Freelancer Profile error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};
