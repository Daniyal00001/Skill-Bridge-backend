import { Request, Response } from "express";
import { prisma } from "../config/prisma";
import {
  uploadToCloudinary,
  deleteFromCloudinary,
} from "../utils/uploadToCloudinary";
import { updateProfileCompletion } from "../utils/profileCompletion";
import { ExperienceLevel, AvailabilityStatus } from "@prisma/client";
import { validateSkillName } from "../utils/skillValidation";
import { checkSkillRateLimit } from "../utils/redis";

// Get Current User Profile
export const getMyFreelancerProfile = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId;
    if (!userId)
      return res.status(401).json({ success: false, message: "Unauthorized" });

    const profile = (await prisma.freelancerProfile.findUnique({
      where: { userId },
      include: {
        skills: true, // Don't include skill nested yet to avoid Prisma crashing on missing refs
        portfolioItems: true,
        certificates: true,
        gigs: true,
        educations: true,
        user: {
          select: {
            email: true,
            name: true,
            firstName: true,
            lastName: true,
            profileImage: true,
            isEmailVerified: true,
            isIdVerified: true,
            idVerificationStatus: true,
            idRejectionReason: true,
            phoneNumber: true,
          },
        },
      },
    })) as any;

    if (!profile)
      return res
        .status(404)
        .json({ success: false, message: "Profile not found" });

    // ── Fetch Related Data for Metrics ──────────────────────
    const contracts = await prisma.contract.findMany({
      where: { freelancerProfileId: profile.id },
      include: {
        project: {
          select: { title: true, budget: true, budgetType: true }
        },
        freelancerProfile: {
           include: { user: { select: { name: true } } }
        }
      }
    });

    const reviews = await prisma.review.findMany({
      where: { 
        receiverId: userId,
        isRevealed: true 
      },
      include: {
        giver: {
          select: { name: true }
        }
      }
    });

    // ── Calculate Metrics ──────────────────────────────────
    const completedContracts = contracts.filter(c => c.status === "COMPLETED");
    const cancelledContracts = contracts.filter(c => c.status === "CANCELLED"); // Assuming CANCELLED exists
    
    const projectsCompleted = completedContracts.length;
    const totalEarnings = completedContracts.reduce((sum, c) => sum + (c.agreedPrice || 0), 0);
    
    // Job Success: (Completed / (Completed + Cancelled))
    // Default to 100% for new profiles
    let jobSuccess = 100;
    const closedCount = projectsCompleted + cancelledContracts.length;
    if (closedCount > 0) {
      jobSuccess = Math.round((projectsCompleted / closedCount) * 100);
    }

    // ── Format Work History ────────────────────────────────
    // Link COMPLETED contracts with their reviews
    const workHistory = completedContracts.map(contract => {
      const review = reviews.find(r => r.contractId === contract.id);
      return {
        id: contract.id,
        title: contract.project?.title || "Project Detail Secure",
        amount: contract.agreedPrice,
        rating: review?.rating || null,
        comment: review?.comment || null,
        date: new Date(contract.endDate || contract.updatedAt).toLocaleDateString('en-US', { month: 'short', year: 'numeric' }),
        client: review?.giver?.name || "Verified Client"
      };
    }).sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());

    // ── Manually fetch and attach skills ──────────────────
    const skillIds = profile.skills.map((s: any) => s.skillId);
    if (skillIds.length > 0) {
      const skillsData = await prisma.skill.findMany({
        where: { id: { in: skillIds } },
      });

      profile.skills = profile.skills
        .map((s: any) => ({
          ...s,
          skill: skillsData.find((sd) => sd.id === s.skillId),
        }))
        .filter((s: any) => s.skill);
    }

    // Prepare final payload
    const data = {
      ...profile,
      projectsCompleted,
      totalEarnings: `$${totalEarnings.toLocaleString()}`,
      jobSuccess: `${jobSuccess}%`,
      workHistory,
      reviewsAvg: profile.averageRating?.toFixed(1) || "5.0",
      reviewsTotal: profile.totalReviews || reviews.length
    };

    return res.status(200).json({ success: true, data });
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
    const { fullName, phoneNumber, location, region, tagline } = req.body;

    if (!userId)
      return res.status(401).json({ success: false, message: "Unauthorized" });

    if (!fullName || fullName.length < 3)
      return res.status(400).json({
        success: false,
        message: "Full name must be at least 3 characters.",
      });
    if (!tagline || tagline.length < 10)
      return res.status(400).json({
        success: false,
        message: "Tagline must be at least 10 characters.",
      });
    if (
      !phoneNumber ||
      !/^\+?[1-9]\d{1,14}$/.test(phoneNumber.replace(/\s/g, ""))
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid phone number format. Must start with '+'.",
      });
    }
    if (!location)
      return res
        .status(400)
        .json({ success: false, message: "Country is required." });

    // Update User model (name)
    const user = await prisma.user.update({
      where: { id: userId },
      data: {
        name: fullName,
        phoneNumber,
      },
    });

    // Update Freelancer Profile
    const profile = await prisma.freelancerProfile.update({
      where: { userId },
      data: {
        location,
        region,
        tagline,
        fullName,
      },
    });

    const newCompletion = await updateProfileCompletion(userId);
    return res.status(200).json({
      success: true,
      data: { ...profile, profileCompletion: newCompletion },
    });
  } catch (error: any) {
    console.error("Update Step 1 error:", error);
    if (error.code === "P2002")
      return res.status(400).json({
        success: false,
        message: "This phone number is already registered.",
      });
    return res.status(500).json({
      success: false,
      message: error.message || "Internal server error",
    });
  }
};

// Step 2: Professional Details
export const updateOnboardingStep2 = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId;
    const {
      hourlyRate,
      bio,
      availability,
      experienceLevel,
      preferredBudgetMin,
      preferredBudgetMax,
    } = req.body;

    if (!userId)
      return res.status(401).json({ success: false, message: "Unauthorized" });
    if (!hourlyRate || Number(hourlyRate) < 5)
      return res
        .status(400)
        .json({ success: false, message: "Minimum hourly rate is $5." });
    if (!bio || bio.length < 100)
      return res.status(400).json({
        success: false,
        message: "Bio must be at least 100 characters.",
      });

    const profile = await prisma.freelancerProfile.update({
      where: { userId },
      data: {
        hourlyRate: parseFloat(hourlyRate),
        bio,
        availability: availability as AvailabilityStatus,
        experienceLevel: experienceLevel as ExperienceLevel,
        preferredBudgetMin: preferredBudgetMin ? parseFloat(preferredBudgetMin) : null,
        preferredBudgetMax: preferredBudgetMax ? parseFloat(preferredBudgetMax) : null,
      },
    });

    const newCompletion = await updateProfileCompletion(userId);
    return res.status(200).json({
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

    if (!userId)
      return res.status(401).json({ success: false, message: "Unauthorized" });
    if (!skills || !Array.isArray(skills) || skills.length === 0) {
      return res
        .status(400)
        .json({ success: false, message: "At least one skill is required." });
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
        let skillObj = await prisma.skill.findUnique({
          where: { name: sk.name },
        });

        if (!skillObj) {
          // Check if skill was previously rejected
          const rejected = await prisma.rejectedSkill.findUnique({
            where: { name: sk.name },
          });
          if (rejected) {
            return res.status(403).json({
              success: false,
              message: `Skill '${sk.name}' is not allowed to be added as it has been flagged as invalid or inappropriate.`,
            });
          }

          const validation = validateSkillName(sk.name);
          if (!validation.valid) {
            return res.status(400).json({
              success: false,
              message: `Skill Error ('${sk.name}'): ${validation.message}`,
            });
          }
          await checkSkillRateLimit(userId);

          skillObj = await prisma.skill.create({
            data: { name: sk.name, category: "General", status: "PENDING" },
          });
        }

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
        user: { select: { profileImage: true, idDocumentUrl: true } },
      },
    });
    if (!profile)
      return res
        .status(404)
        .json({ success: false, message: "Profile not found" });

    // Validate Limit
    const newCerts = files["certFiles"] ? files["certFiles"].length : 0;
    const newGigs = files["gigFiles"] ? files["gigFiles"].length : 0;

    if (profile.certificates.length + newCerts > 4) {
      return res.status(400).json({
        success: false,
        message: `Total certificates would exceed limit of 4. Already have ${profile.certificates.length}.`,
      });
    }

    if (profile.gigs.length + newGigs > 4) {
      return res.status(400).json({
        success: false,
        message: `Total gigs would exceed limit of 4. Already have ${profile.gigs.length}.`,
      });
    }

    const updates: any = {};

    // Upload ID
    if (files["idDocument"] && files["idDocument"][0]) {
      const idDoc = files["idDocument"][0];

      // 1. Check Status: Only allow if UNSUBMITTED or REJECTED
      if (profile.user.idVerificationStatus === "PENDING" || profile.user.idVerificationStatus === "APPROVED") {
        return res.status(400).json({
          success: false,
          message: `Cannot upload ID document while status is ${profile.user.idVerificationStatus}.`
        });
      }

      // 2. Check File Type: Only allow images (not PDF)
      const allowedImageTypes = ["image/jpeg", "image/png", "image/webp", "image/jpg"];
      if (!allowedImageTypes.includes(idDoc.mimetype)) {
        return res.status(400).json({
          success: false,
          message: "Only image files (JPEG, PNG, WEBP) are allowed for identity verification."
        });
      }

      // Delete old one if exists
      if (profile.user.idDocumentUrl) {
        await deleteFromCloudinary(profile.user.idDocumentUrl);
      }

      const idUrl = await uploadToCloudinary(idDoc.buffer, idDoc.originalname, idDoc.mimetype);
      await prisma.user.update({
        where: { id: userId },
        data: { idDocumentUrl: idUrl, idVerificationStatus: "PENDING" },
      });
      updates.idDocumentUrl = idUrl;
    }


    // Profile Pic
    if (files["profileImage"] && files["profileImage"][0]) {
      // Delete old one if exists
      if (profile.user.profileImage) {
        await deleteFromCloudinary(profile.user.profileImage);
      }

      const picUrl = await uploadToCloudinary(files["profileImage"][0].buffer, files["profileImage"][0].originalname, files["profileImage"][0].mimetype);
      await prisma.user.update({
        where: { id: userId },
        data: { profileImage: picUrl },
      });
      updates.profileImage = picUrl;
    }

    // Certs
    if (files["certFiles"]) {
      const certTitles = req.body.certTitles
        ? Array.isArray(req.body.certTitles)
          ? req.body.certTitles
          : req.body.certTitles.split(",")
        : [];
      for (let i = 0; i < files["certFiles"].length; i++) {
        const url = await uploadToCloudinary(files["certFiles"][i].buffer, files["certFiles"][i].originalname, files["certFiles"][i].mimetype);
        await prisma.certificate.create({
          data: {
            freelancerProfileId: profile.id,
            title: certTitles[i] || `Certificate ${i + 1}`,
            issuingOrganization: "Uploaded",
            issueDate: new Date(),
            credentialUrl: url,
          },
        });
      }
    }

    // Gigs
    if (files["gigFiles"]) {
      const gigTitles = req.body.gigTitles
        ? Array.isArray(req.body.gigTitles)
          ? req.body.gigTitles
          : req.body.gigTitles.split(",")
        : [];
      for (let i = 0; i < files["gigFiles"].length; i++) {
        const url = await uploadToCloudinary(files["gigFiles"][i].buffer, files["gigFiles"][i].originalname, files["gigFiles"][i].mimetype);
        await prisma.gig.create({
          data: {
            freelancerProfileId: profile.id,
            title: gigTitles[i] || `Gig ${i + 1}`,
            fileUrl: url,
          },
        });
      }
    }

    // Increment completion
    const newCompletion = await updateProfileCompletion(userId);

    return res.status(200).json({
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
    const { github, linkedin, portfolio, website, preferredCategories } =
      req.body;

    if (
      preferredCategories &&
      Array.isArray(preferredCategories) &&
      preferredCategories.length > 4
    ) {
      return res.status(400).json({
        success: false,
        message: "You can select a maximum of 4 preferred categories.",
      });
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
    return res.status(200).json({
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
      fullName,
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
      preferredBudgetMin,
      preferredBudgetMax,
    } = req.body;

    if (
      preferredCategories &&
      Array.isArray(preferredCategories) &&
      preferredCategories.length > 4
    ) {
      return res.status(400).json({
        success: false,
        message: "You can select a maximum of 4 preferred categories.",
      });
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
    if (fullName !== undefined) userUpdateData.name = fullName;
    // Handle File removal (if explicitly passed as empty string or null to delete)
    if (idDocumentUrl === null || idDocumentUrl === "") {
      userUpdateData.idDocumentUrl = null;
      userUpdateData.isIdVerified = false;
      userUpdateData.idVerificationStatus = "UNSUBMITTED";
      userUpdateData.idRejectionReason = null;
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
    if (fullName !== undefined) {
      profileUpdateData.fullName = fullName;
    }
    if (preferredBudgetMin !== undefined)
      profileUpdateData.preferredBudgetMin = preferredBudgetMin ? parseFloat(preferredBudgetMin) : null;
    if (preferredBudgetMax !== undefined)
      profileUpdateData.preferredBudgetMax = preferredBudgetMax ? parseFloat(preferredBudgetMax) : null;

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
        let skillObj = await prisma.skill.findUnique({
          where: { name: skillName },
        });

        if (!skillObj) {
          // Check if skill was previously rejected
          const rejected = await prisma.rejectedSkill.findUnique({
            where: { name: skillName },
          });
          if (rejected) {
            return res.status(403).json({
              success: false,
              message: `Skill '${skillName}' is not allowed to be added as it has been flagged as invalid or inappropriate.`,
            });
          }

          const validation = validateSkillName(skillName);
          if (!validation.valid) {
            return res.status(400).json({
              success: false,
              message: `Skill Error ('${skillName}'): ${validation.message}`,
            });
          }
          await checkSkillRateLimit(userId);

          skillObj = await prisma.skill.create({
            data: { name: skillName, category: "General", status: "PENDING" },
          });
        }
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

    const updatedProfile = (await prisma.freelancerProfile.findUnique({
      where: { userId },
      include: {
        skills: true, // Don't include skill nested yet
        portfolioItems: true,
        certificates: true,
        educations: true,
        gigs: true,
        user: {
          select: {
            email: true,
            name: true,
            firstName: true,
            lastName: true,
            profileImage: true,
            isEmailVerified: true,
            isIdVerified: true,
          },
        },
      } as any,
    })) as any;

    if (updatedProfile) {
      const sIds = updatedProfile.skills.map((s: any) => s.skillId);
      if (sIds.length > 0) {
        const sData = await prisma.skill.findMany({
          where: { id: { in: sIds } },
        });
        updatedProfile.skills = updatedProfile.skills
          .map((s: any) => ({
            ...s,
            skill: sData.find((sd) => sd.id === s.skillId),
          }))
          .filter((s: any) => s.skill);
      }
    }

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
