import { Request, Response } from 'express'
import { prisma } from '../config/prisma'
import { uploadToCloudinary } from "../utils/uploadToCloudinary"
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
      category,
      subCategory,
      budget,
      budgetType,
      projectSize,
      deadline,
      skills,
      experienceLevel,
      hiringMethod,
      language,
      locationPref,
      status = 'OPEN'
    } = req.body

    // Handle uploaded files (from upload.middleware)
 const attachments: string[] = []

if (req.files && Array.isArray(req.files)) {
  for (const file of req.files as Express.Multer.File[]) {

    const url = await uploadToCloudinary(file.buffer)

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
        category,
        subCategory,
        budget: Number(budget),
        budgetType,
        size: sizeMap[projectSize] || 'MEDIUM',
        deadline: deadline ? new Date(deadline) : null,
        attachments,
        experienceLevel,
        hiringMethod,
        language,
        locationPref,
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
          skill = await prisma.skill.create({
            data: {
              name: skillName,
              category: category || 'other'
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
        skills: {
          include: { skill: true }
        }
      }
    })

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
      referenceLinks, category, subCategory, budget,
      budgetType, projectSize, deadline, skills,
      experienceLevel, hiringMethod, language, locationPref, status
    } = req.body

    const sizeMap: Record<string, 'SMALL' | 'MEDIUM' | 'LARGE'> = {
      small: 'SMALL', medium: 'MEDIUM', large: 'LARGE',
    }

    const newAttachments: string[] = []
    if (req.files && Array.isArray(req.files)) {
      for (const file of req.files as Express.Multer.File[]) {
        const url = await uploadToCloudinary(file.buffer)
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
        ...(category && { category }),
        ...(subCategory && { subCategory }),
        ...(budget && { budget: Number(budget) }),
        ...(budgetType && { budgetType }),
        ...(projectSize && { size: sizeMap[projectSize] }),
        ...(deadline && { deadline: new Date(deadline) }),
        ...(experienceLevel && { experienceLevel }),
        ...(hiringMethod && { hiringMethod }),
        ...(language && { language }),
        ...(locationPref && { locationPref }),
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
          skill = await prisma.skill.create({
            data: { name: skillName, category: category || 'other' }
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
    const { category, skills, experienceLevel, budgetMin, budgetMax } = req.query

    const projects = await prisma.project.findMany({
      where: {
        status: 'OPEN',
        ...(category && { category: String(category) }),
        ...(experienceLevel && { experienceLevel: String(experienceLevel) }),
        ...(budgetMin || budgetMax ? {
          budget: {
            ...(budgetMin && { gte: Number(budgetMin) }),
            ...(budgetMax && { lte: Number(budgetMax) }),
          }
        } : {}),
      },
      include: {
        skills: { include: { skill: true } },
        clientProfile: {
          select: { fullName: true, company: true }
        }
      },
      orderBy: { createdAt: 'desc' }
    })

    return res.status(200).json({
      success: true,
      projects
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

    const projects = await prisma.project.findMany({
      where: {
        clientProfileId: clientProfile.id,
        ...(status && { status: String(status) as any }),
      },
      include: {
        skills: { include: { skill: true } },
        proposals: { select: { id: true } }
      },
      orderBy: { createdAt: 'desc' }
    })

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
        skills: { include: { skill: true } },
        clientProfile: {
          select: { fullName: true, company: true, location: true }
        },
        proposals: { select: { id: true } }
      }
    })

    if (!project) {
      return res.status(404).json({ success: false, message: 'Project not found.' })
    }

    // Increment view count
    await prisma.project.update({
      where: { id },
      data: { viewCount: { increment: 1 } }
    })

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
  console.log("delete project route called")
  try {
    const userId = req.user?.userId
    const id = req.params.id as string

    const clientProfile = await prisma.clientProfile.findUnique({ where: { userId } })

    if (!clientProfile) {
      return res.status(404).json({ success: false, message: 'Client profile not found.' })
    }

    const project = await prisma.project.findUnique({ where: { id } })

    if (!project) {
      return res.status(404).json({ success: false, message: 'Project not found.' })
    }

    if (project.clientProfileId !== clientProfile.id) {
      return res.status(403).json({ success: false, message: 'Not authorized.' })
    }

    if (!['DRAFT', 'OPEN'].includes(project.status)) {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete a project that is already in progress.'
      })
    }

    await prisma.project.delete({ where: { id } })

    return res.status(200).json({ success: true, message: 'Project deleted successfully.' })

  } catch (error) {
    console.error('Delete project error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}