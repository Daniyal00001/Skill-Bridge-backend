import { Request, Response } from 'express'
import { prisma } from '../config/prisma'

/**
 * @desc    Get all proposals submitted by the logged-in freelancer
 * @route   GET /api/proposals/my
 * @access  Private (Freelancer only)
 */
export const getMyProposals = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId

    if (!userId) {
      return res.status(401).json({ success: false, message: 'Unauthorized' })
    }

    // Find the freelancer profile
    const freelancerProfile = await prisma.freelancerProfile.findUnique({
      where: { userId }
    })

    if (!freelancerProfile) {
      return res.status(404).json({
        success: false,
        message: 'Freelancer profile not found'
      })
    }

    const proposals = await prisma.proposal.findMany({
      where: {
        freelancerProfileId: freelancerProfile.id
      },
      include: {
        project: {
          include: {
            category: true,
            clientProfile: {
              select: {
                fullName: true,
              }
            }
          }
        }
      },
      orderBy: {
        submittedAt: 'desc'
      }
    })

    const formattedProposals = proposals.map(p => ({
      id: p.id,
      bidAmount: p.proposedPrice,
      deliveryDays: p.deliveryTime,
      coverLetter: p.coverLetter,
      status: p.status,
      createdAt: p.submittedAt,
      project: {
        id: p.project.id,
        title: p.project.title,
        budget: p.project.budget,
        category: p.project.category, 
        client: {
          name: p.project.clientProfile.fullName,
        }
      }
    }))

    return res.status(200).json({
      success: true,
      proposals: formattedProposals
    })

  } catch (error) {
    console.error('Get My Proposals error:', error)
    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    })
  }
}
