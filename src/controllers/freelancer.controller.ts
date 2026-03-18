import { Request, Response } from 'express'
import { prisma } from '../config/prisma'
import { Prisma, Role } from '@prisma/client'

/**
 * @desc    Get all freelancers with advanced filtering and pagination
 * @route   GET /api/freelancers
 * @access  Private (Protect middleware should be applied)
 */
export const getAllFreelancers = async (req: Request, res: Response) => {
  try {
    const {
      search,
      skills,
      minRate,
      maxRate,
      experienceLevel,
      availability,
      page = 1,
      limit = 25,
      sortBy = 'createdAt',
      sortOrder = 'desc',
    } = req.query

    const pageNumber = parseInt(page as string) || 1
    const limitNumber = parseInt(limit as string) || 25
    const skip = (pageNumber - 1) * limitNumber

    // Dynamic filtering
    const where: Prisma.FreelancerProfileWhereInput = {}

    // Search filter (Name, Tagline, Bio)
    if (search) {
      where.OR = [
        { fullName: { contains: search as string, mode: 'insensitive' } },
        { tagline: { contains: search as string, mode: 'insensitive' } },
        { bio: { contains: search as string, mode: 'insensitive' } },
      ]
    }

    // Skills filter
    if (skills) {
      const skillList = (skills as string).split(',').map(s => s.trim())
      where.skills = {
        some: {
          skill: {
            name: { in: skillList, mode: 'insensitive' }
          }
        }
      }
    }

    // Rate filter
    if (minRate || maxRate) {
      where.hourlyRate = {}
      if (minRate) where.hourlyRate.gte = parseFloat(minRate as string)
      if (maxRate) where.hourlyRate.lte = parseFloat(maxRate as string)
    }

    // Experience Level filter
    if (experienceLevel) {
      where.experienceLevel = experienceLevel as any
    }

    // Availability filter
    if (availability) {
      where.availability = availability as any
    }

    // Sorting
    const orderBy: any = {}
    if (sortBy === 'hourlyRate') {
      orderBy.hourlyRate = sortOrder === 'asc' ? 'asc' : 'desc'
    } else {
      orderBy.user = {
        createdAt: sortOrder === 'asc' ? 'asc' : 'desc'
      }
    }

    // Execute query
    const [freelancers, totalCount] = await Promise.all([
      prisma.freelancerProfile.findMany({
        where,
        include: {
          user: {
            select: {
              profileImage: true,
              isEmailVerified: true,
            }
          },
          skills: {
            include: {
              skill: true
            }
          }
        },
        orderBy,
        skip,
        take: limitNumber,
      }),
      prisma.freelancerProfile.count({ where }),
    ])

    // Calculate pagination metadata
    const totalPages = Math.ceil(totalCount / limitNumber)

    return res.status(200).json({
      success: true,
      message: 'Freelancers fetched successfully',
      data: {
        freelancers,
        pagination: {
          total: totalCount,
          page: pageNumber,
          limit: limitNumber,
          totalPages,
        }
      }
    })

  } catch (error) {
    console.error('Get all freelancers error:', error)
    return res.status(500).json({
      success: false,
      message: 'Internal server error',
    })
  }
}

/**
 * @desc    Get single freelancer profile details
 * @route   GET /api/freelancers/:id
 * @access  Private
 */
export const getFreelancerById = async (req: Request, res: Response) => {
  try {
    const { id } = req.params

    const freelancer = await prisma.freelancerProfile.findUnique({
      where: { id },
      include: {
        user: {
          select: {
            name: true,
            email: true,
            profileImage: true,
            isEmailVerified: true,
            createdAt: true,
            lastActiveAt: true,
          }
        },
        skills: {
          include: {
            skill: true
          }
        },
        portfolioItems: true,
        certificates: true,
        proposals: {
          take: 5,
          where: { status: 'ACCEPTED' },
          include: {
            project: {
              select: {
                title: true,
                budget: true,
              }
            }
          }
        }
      }
    })

    if (!freelancer) {
      return res.status(404).json({
        success: false,
        message: 'Freelancer profile not found'
      })
    }

    return res.status(200).json({
      success: true,
      data: freelancer
    })
  } catch (error) {
    console.error('Get freelancer by ID error:', error)
    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    })
  }
}

/**
 * @desc    Invite a freelancer to a project
 * @route   POST /api/freelancers/:id/invite
 * @access  Private (Role: CLIENT)
 */
export const inviteFreelancer = async (req: Request, res: Response) => {
  try {
    const { id: freelancerProfileId } = req.params
    const { projectId, message } = req.body
    const userId = (req as any).user?.userId

    if (!projectId) {
      return res.status(400).json({
        success: false,
        message: 'Project ID is required for invitation'
      })
    }

    // Verify client profile
    const clientProfile = await prisma.clientProfile.findUnique({
      where: { userId }
    })

    if (!clientProfile) {
      return res.status(403).json({
        success: false,
        message: 'Only clients can invite freelancers'
      })
    }

    // Check project ownership
    const project = await prisma.project.findUnique({
      where: { id: projectId }
    })

    if (!project || project.clientProfileId !== clientProfile.id) {
      return res.status(403).json({
        success: false,
        message: 'You can only invite to your own projects'
      })
    }

    // Check if freelancer exists
    const freelancer = await prisma.freelancerProfile.findUnique({
      where: { id: freelancerProfileId }
    })

    if (!freelancer) {
      return res.status(404).json({
        success: false,
        message: 'Freelancer not found'
      })
    }

    // Check for existing invitation or proposal
    const existingInvite = await prisma.invitation.findUnique({
      where: {
        projectId_freelancerProfileId: {
          projectId,
          freelancerProfileId
        }
      }
    })

    if (existingInvite) {
      return res.status(400).json({
        success: false,
        message: 'Freelancer is already invited to this project'
      })
    }

    // Create invitation
    const invitation = await prisma.invitation.create({
      data: {
        projectId,
        freelancerProfileId,
        clientProfileId: clientProfile.id,
        message,
      }
    })

    // Create notification for freelancer
    await prisma.notification.create({
      data: {
        userId: freelancer.userId,
        type: 'INVITATION_RECEIVED',
        title: 'New Project Invitation',
        body: `${clientProfile.fullName} invited you to work on: ${project.title}`,
        link: `/freelancer/invitations/${invitation.id}`
      }
    })

    return res.status(201).json({
      success: true,
      message: 'Invitation sent successfully',
      data: invitation
    })

  } catch (error) {
    console.error('Invite freelancer error:', error)
    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    })
  }
}

/**
 * @desc    Initiate or get a chat room for recruitment
 * @route   POST /api/freelancers/:id/message
 * @access  Private
 */
export const initiateChat = async (req: Request, res: Response) => {
  try {
    const { id: freelancerProfileId } = req.params
    const { projectId } = req.body
    const userId = (req as any).user?.userId

    // Find profiles
    const clientProfile = await prisma.clientProfile.findUnique({
      where: { userId }
    })

    if (!clientProfile) {
      return res.status(403).json({
        success: false,
        message: 'Only clients can initiate recruitment chats'
      })
    }

    const freelancer = await prisma.freelancerProfile.findUnique({
      where: { id: freelancerProfileId }
    })

    if (!freelancer) {
      return res.status(404).json({
        success: false,
        message: 'Freelancer not found'
      })
    }

    // Check for existing chat room (either linked to this project or a general recruitment one)
    let chatRoom = await prisma.chatRoom.findFirst({
      where: {
        freelancerProfileId,
        clientProfileId: clientProfile.id,
        projectId: projectId || null,
        contractId: null // Only looking for recruitment chats here
      }
    })

    if (!chatRoom) {
      // Create new chat room
      chatRoom = await prisma.chatRoom.create({
        data: {
          freelancerProfileId,
          clientProfileId: clientProfile.id,
          projectId: projectId || null,
        }
      })
    }

    return res.status(200).json({
      success: true,
      data: chatRoom
    })

  } catch (error) {
    console.error('Initiate chat error:', error)
    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    })
  }
}
