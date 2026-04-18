import { Request, Response } from 'express'
import { prisma } from '../config/prisma'
import * as notificationService from '../services/notification.service'
import { uploadToCloudinary } from "../utils/uploadToCloudinary"
import { validateSkillName } from "../utils/skillValidation";
import { checkSkillRateLimit } from "../utils/redis";
// ─────────────────────────────────────────────────────────────
// CREATE PROJECT (Client only)
// POST /api/projects
// ─────────────────────────────────────────────────────────────
export const createProject = async (req: Request, res: Response) => {
   console.log("create project route called")
  try {
    const userId = req.user?.userId

    // Get client profile
    const clientProfile = await prisma.clientProfile.findUnique({
      where: { userId }
    })

    if (!clientProfile) {
      return res.status(404).json({
        success: false,
        message: 'Client profile not found.'
      })
    }

    const {
      title,
      shortDesc,
      description,
      requirements,
      referenceLinks,
      categoryId,
      subCategoryId,
      budget,
      budgetType,
      projectSize,
      deadline,
      skills,
      experienceLevel,
      hiringMethod,
      language,
      locationPref,
      languageId,
      locationId,
      status = 'OPEN'
    } = req.body

    // Handle uploaded files (from upload.middleware)
 const attachments: string[] = []

if (req.files && Array.isArray(req.files)) {
  for (const file of req.files as Express.Multer.File[]) {

    const url = await uploadToCloudinary(file.buffer, file.originalname, file.mimetype)

    attachments.push(url)
  }
}

    // Map projectSize string to enum
    const sizeMap: Record<string, 'SMALL' | 'MEDIUM' | 'LARGE'> = {
      small: 'SMALL',
      medium: 'MEDIUM',
      large: 'LARGE',
    }

    const project = await prisma.project.create({
      data: {
        clientProfileId: clientProfile.id,
        title,
        shortDesc,
        description,
        requirements,
        referenceLinks,
        categoryId,
        subCategoryId,
        budget: Number(budget),
        budgetType,
        size: sizeMap[projectSize] || 'MEDIUM',
        deadline: deadline ? new Date(deadline) : null,
        attachments,
        experienceLevel,
        hiringMethod,
        language,
        locationPref,
        languageId,
        locationId,
        status,
      }
    })

    // Attach skills if provided
    let parsedSkills: string[] = []
    if (skills) {
      if (typeof skills === 'string') parsedSkills = [skills]
      else if (Array.isArray(skills)) parsedSkills = skills
    }

    if (parsedSkills.length > 0) {
      for (const skillName of parsedSkills) {
        // Find or create skill
        let skill = await prisma.skill.findFirst({
          where: { name: { equals: skillName } }
        })

        if (!skill) {
          // Check if skill was previously rejected
          const rejected = await prisma.rejectedSkill.findUnique({ where: { name: skillName } });
          if (rejected) {
            return res.status(403).json({ 
              success: false, 
              message: `Skill '${skillName}' is not allowed to be added as it has been flagged as invalid or inappropriate.` 
            });
          }

          const validation = validateSkillName(skillName);
          if (!validation.valid) {
            return res.status(400).json({ success: false, message: `Skill Error ('${skillName}'): ${validation.message}` });
          }
          await checkSkillRateLimit(userId);

          skill = await prisma.skill.create({
            data: {
              name: skillName,
              category: 'other',
              status: 'PENDING'
            }
          })
        }

        await prisma.projectSkill.create({
          data: {
            projectId: project.id,
            skillId: skill.id
          }
        })
      }
    }

    // Return project with skills
    const fullProject = await prisma.project.findUnique({
      where: { id: project.id },
      include: {
        skills: true, // Don't include skill nested yet
      }
    }) as any;

    if (fullProject) {
      const sIds = fullProject.skills.map((s: any) => s.skillId);
      if (sIds.length > 0) {
        const sData = await prisma.skill.findMany({
          where: { id: { in: sIds } }
        });
        fullProject.skills = fullProject.skills.map((s: any) => ({
          ...s,
          skill: sData.find(sd => sd.id === s.skillId)
        })).filter((s: any) => s.skill);
      }
    }

    return res.status(201).json({
      success: true,
      message: status === 'DRAFT' ? 'Draft saved successfully.' : 'Project posted successfully.',
      project: fullProject
    })

  } catch (error) {
    console.error('Create project error:', error)
    return res.status(500).json({
      success: false,
      message: 'Internal server error.'
    })
  }
}


// ─────────────────────────────────────────────────────────────
// UPDATE PROJECT / PUBLISH DRAFT (Client only)
// PATCH /api/projects/:id
// ─────────────────────────────────────────────────────────────
export const updateProject = async (req: Request, res: Response) => {
   console.log("update project route called")
  try {
    const userId = req.user?.userId
    const id = req.params.id as string

    const clientProfile = await prisma.clientProfile.findUnique({
      where: { userId }
    })

    if (!clientProfile) {
      return res.status(404).json({ success: false, message: 'Client profile not found.' })
    }

    // Make sure this project belongs to this client
    const existing = await prisma.project.findUnique({ where: { id } })

    if (!existing) {
      return res.status(404).json({ success: false, message: 'Project not found.' })
    }

    if (existing.clientProfileId !== clientProfile.id) {
      return res.status(403).json({ success: false, message: 'Not authorized.' })
    }

    const {
      title, shortDesc, description, requirements,
      referenceLinks, categoryId, subCategoryId, budget,
      budgetType, projectSize, deadline, skills,
      experienceLevel, hiringMethod, language, locationPref, 
      languageId, locationId, status
    } = req.body

    const sizeMap: Record<string, 'SMALL' | 'MEDIUM' | 'LARGE'> = {
      small: 'SMALL', medium: 'MEDIUM', large: 'LARGE',
    }

    const newAttachments: string[] = []
    if (req.files && Array.isArray(req.files)) {
      for (const file of req.files as Express.Multer.File[]) {
        const url = await uploadToCloudinary(file.buffer, file.originalname, file.mimetype)
        newAttachments.push(url)
      }
    }

    const updated = await prisma.project.update({
      where: { id },
      data: {
        ...(title && { title }),
        ...(shortDesc && { shortDesc }),
        ...(description && { description }),
        ...(requirements && { requirements }),
        ...(referenceLinks && { referenceLinks }),
        ...(categoryId && { categoryId }),
        ...(subCategoryId && { subCategoryId }),
        ...(budget && { budget: Number(budget) }),
        ...(budgetType && { budgetType }),
        ...(projectSize && { size: sizeMap[projectSize] }),
        ...(deadline && { deadline: new Date(deadline) }),
        ...(experienceLevel && { experienceLevel }),
        ...(hiringMethod && { hiringMethod }),
        ...(language && { language }),
        ...(locationPref && { locationPref }),
        ...(languageId && { languageId }),
        ...(locationId && { locationId }),
        ...(status && { status }),
        ...(newAttachments.length > 0 && { attachments: [...(existing.attachments || []), ...newAttachments] }),
      }
    })

    // Update skills if provided
    let parsedSkills: string[] = []
    if (skills) {
      if (typeof skills === 'string') parsedSkills = [skills]
      else if (Array.isArray(skills)) parsedSkills = skills
    }

    if (parsedSkills.length > 0) {
      // Delete old skills
      await prisma.projectSkill.deleteMany({ where: { projectId: id } })

      for (const skillName of parsedSkills) {
        let skill = await prisma.skill.findFirst({
          where: { name: { equals: skillName } }
        })
        if (!skill) {
          // Check if skill was previously rejected
          const rejected = await prisma.rejectedSkill.findUnique({ where: { name: skillName } });
          if (rejected) {
            return res.status(403).json({ 
              success: false, 
              message: `Skill '${skillName}' is not allowed to be added as it has been flagged as invalid or inappropriate.` 
            });
          }

          const validation = validateSkillName(skillName);
          if (!validation.valid) {
             return res.status(400).json({ success: false, message: `Skill Error ('${skillName}'): ${validation.message}` });
          }
          await checkSkillRateLimit(userId);
          
          skill = await prisma.skill.create({
            data: { name: skillName, category: 'other', status: 'PENDING' }
          })
        }
        await prisma.projectSkill.create({
          data: { projectId: id, skillId: skill.id }
        })
      }
    }

    return res.status(200).json({
      success: true,
      message: 'Project updated successfully.',
      project: updated
    })

  } catch (error) {
    console.error('Update project error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}


// ─────────────────────────────────────────────────────────────
// GET ALL OPEN PROJECTS (Freelancer browses)
// GET /api/projects
// ─────────────────────────────────────────────────────────────
export const getAllProjects = async (req: Request, res: Response) => {
  console.log("get all project route called")
  try {
    const { 
      category, 
      skills, 
      experienceLevel, 
      budgetMin, 
      budgetMax, 
      projectSize,
      search,
      isClientVerified,
      page = 1,
      limit = 25
    } = req.query

    const pageNum = Number(page)
    const limitNum = Number(limit)
    const skip = (pageNum - 1) * limitNum

    const where: any = {
      status: 'OPEN',
      hiringMethod: 'bidding'
    }

    if (isClientVerified === 'true') {
      where.clientProfile = {
        user: {
          isIdVerified: true
        }
      }
    }


    // Search filter
    if (search) {
      where.OR = [
        { title: { contains: String(search), mode: 'insensitive' } },
        { description: { contains: String(search), mode: 'insensitive' } },
      ]
    }

    // Category filter (by slug)
    if (category && category !== 'All') {
      where.category = { slug: String(category) }
    }

    // Experience Level filter
    if (experienceLevel) {
      where.experienceLevel = String(experienceLevel)
    }

    // Project Size filter
    if (projectSize) {
      where.size = String(projectSize).toUpperCase()
    }

    // Budget range filter
    if (budgetMin || budgetMax) {
      where.budget = {
        ...(budgetMin && { gte: Number(budgetMin) }),
        ...(budgetMax && { lte: Number(budgetMax) }),
      }
    }

    // Fetch projects with pagination
    const [projectsRaw, total] = await Promise.all([
      prisma.project.findMany({
        where,
        include: {
          skills: true, // Don't include skill nested yet
          clientProfile: {
            select: { 
              fullName: true, 
              company: true, 
              averageRating: true, 
              totalReviews: true,
              createdAt: true,
              totalHires: true,
              totalSpent: true,
              hireRate: true,
              user: {
                select: {
                  profileImage: true,
                  name: true,
                  isIdVerified: true,
                  isPaymentVerified: true,
                  idVerificationStatus: true,
                }
              }
            }
          },
          category: true,
          languageObj: true,
          locationObj: true,
          _count: { select: { proposals: true } }
        },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limitNum,
      }),
      prisma.project.count({ where })
    ])

    const projects = await Promise.all((projectsRaw as any[]).map(async (p) => {
      const sIds = p.skills.map((s: any) => s.skillId);
      if (sIds.length > 0) {
         const sData = await prisma.skill.findMany({ where: { id: { in: sIds } } });
         p.skills = p.skills.map((s: any) => ({
           ...s,
           skill: sData.find(sd => sd.id === s.skillId)
         })).filter((s: any) => s.skill);
      }
      return p;
    }));

    return res.status(200).json({
      success: true,
      projects,
      pagination: {
        total,
        page: pageNum,
        limit: limitNum,
        totalPages: Math.ceil(total / limitNum)
      }
    })

  } catch (error) {
    console.error('Get projects error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}


// ─────────────────────────────────────────────────────────────
// GET CLIENT'S OWN PROJECTS
// GET /api/projects/my
// ─────────────────────────────────────────────────────────────
export const getMyProjects = async (req: Request, res: Response) => {

   console.log("get my project route called")
  try {
    const userId = req.user?.userId
    const { status } = req.query

    const clientProfile = await prisma.clientProfile.findUnique({ where: { userId } })

    if (!clientProfile) {
      return res.status(404).json({ success: false, message: 'Client profile not found.' })
    }

    const projectsRaw = await prisma.project.findMany({
      where: {
        clientProfileId: clientProfile.id,
        ...(status && { status: String(status) as any }),
      },
      include: {
        skills: true, 
        proposals: { select: { id: true } },
        contract: { select: { id: true } },
        _count: { select: { proposals: true } }
      },
      orderBy: { createdAt: 'desc' }
    })

    const projects = await Promise.all((projectsRaw as any[]).map(async (p) => {
      const sIds = p.skills.map((s: any) => s.skillId);
      if (sIds.length > 0) {
        const sData = await prisma.skill.findMany({ where: { id: { in: sIds } } });
        p.skills = p.skills.map((s: any) => ({
          ...s,
          skill: sData.find(sd => sd.id === s.skillId)
        })).filter((s: any) => s.skill);
      }
      return p;
    }));

    return res.status(200).json({ success: true, projects })

  } catch (error) {
    console.error('Get my projects error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}


// ─────────────────────────────────────────────────────────────
// GET SINGLE PROJECT
// GET /api/projects/:id
// ─────────────────────────────────────────────────────────────
export const getProjectById = async (req: Request, res: Response) => {
  console.log("get project route called")
  try {
    const id = req.params.id as string

    const project = await prisma.project.findUnique({
      where: { id },
      include: {
        skills: true,
        clientProfile: {
          select: { 
            fullName: true, 
            company: true, 
            location: true, 
            averageRating: true, 
            totalReviews: true, 
            createdAt: true, 

            totalHires: true,
            totalSpent: true,
            hireRate: true,
            user: {
              select: {
                id: true,
                profileImage: true,
                name: true,
                isIdVerified: true,
                isPaymentVerified: true,
                idVerificationStatus: true,
              },
            },
            _count: { select: { projects: true } },
          },
        },
        proposals: { select: { id: true } },
        category: true,
        subCategory: true,
        languageObj: true,
        locationObj: true,
        _count: { select: { proposals: true } }
      }
    }) as any;

    if (project) {
      const sIds = project.skills.map((s: any) => s.skillId);
      if (sIds.length > 0) {
        const sData = await prisma.skill.findMany({ where: { id: { in: sIds } } });
        project.skills = project.skills.map((s: any) => ({
          ...s,
          skill: sData.find(sd => sd.id === s.skillId)
        })).filter((s: any) => s.skill);
      }
    }

    if (!project) {
      return res.status(404).json({ success: false, message: 'Project not found.' })
    }

    // Increment view count only if viewer is freelancer
    if (req.user?.role === 'FREELANCER') {
      await prisma.project.update({
        where: { id },
        data: { viewCount: { increment: 1 } }
      })
    }

    return res.status(200).json({ success: true, project })

  } catch (error) {
    console.error('Get project error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}


// ─────────────────────────────────────────────────────────────
// DELETE PROJECT (Client only, only if DRAFT or OPEN)
// DELETE /api/projects/:id
// ─────────────────────────────────────────────────────────────
export const deleteProject = async (req: Request, res: Response) => {
  console.log("soft delete project route called")
  try {
    const userId = req.user?.userId
    const id = req.params.id as string

    const clientProfile = await prisma.clientProfile.findUnique({ where: { userId } })
    if (!clientProfile) {
      return res.status(404).json({ success: false, message: 'Client profile not found.' })
    }

    const project = await prisma.project.findUnique({
      where: { id },
      include: {
        proposals: {
          include: {
            freelancerProfile: true
          }
        }
      }
    })

    if (!project) {
      return res.status(404).json({ success: false, message: 'Project not found.' })
    }

    if (project.clientProfileId !== clientProfile.id) {
      return res.status(403).json({ success: false, message: 'Not authorized.' })
    }

    // Allow cancellation for DRAFT and OPEN projects. 
    // If it's OPEN, we need to refund tokens.
    if (!['DRAFT', 'OPEN'].includes(project.status)) {
      return res.status(400).json({
        success: false,
        message: 'Cannot cancel a project that is already in progress or completed.'
      })
    }

    // Use a transaction for atomic update, refunds, and notifications
    await prisma.$transaction(async (tx) => {
      // 1. Update project status to CANCELLED
      await tx.project.update({
        where: { id },
        data: { status: 'CANCELLED' }
      })

      // 1.1 Update all proposals of this project to CANCELLED
      await tx.proposal.updateMany({
        where: { projectId: id },
        data: { status: 'CANCELLED' as any }
      })

      // 2. Process refunds and notifications for active proposals
      for (const proposal of project.proposals) {
        // Only refund for non-withdrawn/rejected if we want, but usually on cancellation everyone gets back tokens
        if (proposal.tokenCost > 0) {
          const newBalance = proposal.freelancerProfile.skillTokenBalance + proposal.tokenCost
          
          // Increment freelancer balance
          await tx.freelancerProfile.update({
            where: { id: proposal.freelancerProfileId },
            data: { skillTokenBalance: newBalance }
          })

          // Create token transaction record
          await tx.tokenTransaction.create({
            data: {
              freelancerProfileId: proposal.freelancerProfileId,
              type: 'CREDIT',
              reason: 'PROJECT_CANCELLED' as any, // casting because of potential delay in prisma-client regeneration
              amount: proposal.tokenCost,
              balanceAfter: newBalance,
              description: `Refund for cancelled project: ${project.title}`,
              relatedProposalId: proposal.id
            }
          })
        }

        // Create notification for bidder
        await notificationService.createNotification({
          userId: proposal.freelancerProfile.userId,
          type: 'SYSTEM_ALERT',
          title: 'Project Cancelled',
          body: `The project "${project.title}" has been cancelled by the client. Your spent skill tokens have been refunded.`,
          link: `/freelancer/proposals`
        }, tx)
      }
    })

    return res.status(200).json({
      success: true,
      message: 'Project cancelled successfully. Bidders have been notified and refunded.'
    })

  } catch (error) {
    console.error('Delete (Cancel) project error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}