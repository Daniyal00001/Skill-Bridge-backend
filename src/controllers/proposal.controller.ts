import { Request, Response } from 'express'
import { prisma } from '../config/prisma'
import { uploadToCloudinary } from '../utils/uploadToCloudinary'
import { calculateTokenCost, calculateTokenCostWithBreakdown } from '../utils/tokenCalculator'

// ─────────────────────────────────────────────────────────────
// GET TOKEN COST FOR A PROJECT (preview before submitting)
// GET /api/proposals/project/:projectId/token-cost
// ─────────────────────────────────────────────────────────────
export const getProjectTokenCost = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { projectId } = req.params

    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { budget: true, budgetType: true, experienceLevel: true, proposalCount: true, size: true }
    })

    if (!project) {
      return res.status(404).json({ success: false, message: 'Project not found.' })
    }

    const breakdown = calculateTokenCostWithBreakdown({
      budget: project.budget,
      budgetType: project.budgetType,
      experienceLevel: project.experienceLevel,
      proposalCount: project.proposalCount,
      projectSize: project.size,
    })

    // Get freelancer's current balance
    let currentBalance = 0
    if (userId) {
      const profile = await prisma.freelancerProfile.findUnique({
        where: { userId },
        select: { skillTokenBalance: true }
      })
      currentBalance = profile?.skillTokenBalance ?? 0
    }

    return res.status(200).json({
      success: true,
      tokenCost: breakdown.totalCost,
      breakdown,
      currentBalance,
      canAfford: currentBalance >= breakdown.totalCost,
    })
  } catch (error) {
    console.error('Get token cost error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────
// SUBMIT PROPOSAL (Freelancer only)
// POST /api/proposals/project/:projectId
// ─────────────────────────────────────────────────────────────
export const submitProposal = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { projectId } = req.params
    const { bidAmount, deliveryDays, coverLetter } = req.body

    // Handle uploaded files
    const attachments: string[] = []
    if (req.files && Array.isArray(req.files)) {
      for (const file of req.files as Express.Multer.File[]) {
        const url = await uploadToCloudinary(file.buffer)
        attachments.push(url)
      }
    }

    if (!bidAmount || !deliveryDays || !coverLetter) {
      return res.status(400).json({
        success: false,
        message: 'bidAmount, deliveryDays, and coverLetter are required.'
      })
    }

    if (coverLetter.length < 50) {
      return res.status(400).json({
        success: false,
        message: 'Cover letter must be at least 50 characters.'
      })
    }

    // Get freelancer profile with token balance
    const freelancerProfile = await prisma.freelancerProfile.findUnique({
      where: { userId },
      select: { id: true, skillTokenBalance: true }
    })

    if (!freelancerProfile) {
      return res.status(404).json({ success: false, message: 'Freelancer profile not found.' })
    }

    // Get project details
    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: {
        id: true,
        budget: true,
        budgetType: true,
        experienceLevel: true,
        proposalCount: true,
        size: true,
        status: true,
        hiringMethod: true,
      }
    })

    if (!project) {
      return res.status(404).json({ success: false, message: 'Project not found.' })
    }

    if (project.status !== 'OPEN') {
      return res.status(400).json({ success: false, message: 'This project is no longer accepting proposals.' })
    }

    if (project.proposalCount >= 50) {
      return res.status(400).json({ success: false, message: 'This project has reached the maximum limit of 50 proposals.' })
    }

    // Check for duplicate proposal
    const existing = await prisma.proposal.findUnique({
      where: {
        projectId_freelancerProfileId: {
          projectId,
          freelancerProfileId: freelancerProfile.id,
        }
      }
    })

    if (existing) {
      return res.status(409).json({ success: false, message: 'You have already submitted a proposal for this project.' })
    }

    // Calculate token cost
    const tokenCost = calculateTokenCost({
      budget: project.budget,
      budgetType: project.budgetType,
      experienceLevel: project.experienceLevel,
      proposalCount: project.proposalCount,
      projectSize: project.size,
    })

    // Check token balance
    if (freelancerProfile.skillTokenBalance < tokenCost) {
      return res.status(402).json({
        success: false,
        message: `Insufficient SkillTokens. You need ${tokenCost} tokens but have ${freelancerProfile.skillTokenBalance}.`,
        tokenCost,
        currentBalance: freelancerProfile.skillTokenBalance,
        shortfall: tokenCost - freelancerProfile.skillTokenBalance,
      })
    }

    const newBalance = freelancerProfile.skillTokenBalance - tokenCost

    // ── Atomic transaction ────────────────────────────────────
    const result = await prisma.$transaction(async (tx) => {
      // 1. Deduct tokens from freelancer wallet
      await tx.freelancerProfile.update({
        where: { id: freelancerProfile.id },
        data: { skillTokenBalance: newBalance }
      })

      // 2. Create proposal
      const proposal = await tx.proposal.create({
        data: {
          projectId,
          freelancerProfileId: freelancerProfile.id,
          proposedPrice: Number(bidAmount),
          deliveryTime: Number(deliveryDays),
          coverLetter,
          attachments: Array.isArray(attachments) ? attachments : [],
          tokenCost,
          status: 'PENDING',
        },
        include: {
          project: {
            select: { title: true, budget: true, clientProfile: { select: { userId: true } } }
          }
        }
      })

      // 3. Record token transaction
      await tx.tokenTransaction.create({
        data: {
          freelancerProfileId: freelancerProfile.id,
          type: 'DEBIT',
          reason: 'PROPOSAL_SUBMITTED',
          amount: tokenCost,
          balanceAfter: newBalance,
          description: `Proposal submitted for: ${proposal.project.title}`,
          relatedProposalId: proposal.id,
        }
      })

      // 4. Increment proposal count on project
      await tx.project.update({
        where: { id: projectId },
        data: { proposalCount: { increment: 1 } }
      })

      // 5. Notify client
      const clientUserId = proposal.project.clientProfile.userId
      await tx.notification.create({
        data: {
          userId: clientUserId,
          type: 'PROPOSAL_RECEIVED',
          title: 'New Proposal Received',
          body: `A freelancer submitted a proposal for: ${proposal.project.title}`,
          link: `/client/projects/${projectId}/proposals`,
        }
      })

      return proposal
    })

    return res.status(201).json({
      success: true,
      message: 'Proposal submitted successfully!',
      proposal: {
        id: result.id,
        bidAmount: result.proposedPrice,
        deliveryDays: result.deliveryTime,
        coverLetter: result.coverLetter,
        status: result.status,
        tokenCost: result.tokenCost,
        createdAt: result.submittedAt,
      },
      tokenCost,
      remainingBalance: newBalance,
    })

  } catch (error) {
    console.error('Submit proposal error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────
// GET MY PROPOSALS (Freelancer)
// GET /api/proposals/my
// ─────────────────────────────────────────────────────────────
export const getMyProposals = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId

    const freelancerProfile = await prisma.freelancerProfile.findUnique({
      where: { userId },
      select: { id: true, skillTokenBalance: true }
    })

    if (!freelancerProfile) {
      return res.status(404).json({ success: false, message: 'Freelancer profile not found.' })
    }

    const proposals = await prisma.proposal.findMany({
      where: { freelancerProfileId: freelancerProfile.id },
      include: {
        project: {
          include: {
            category: true,
            clientProfile: {
              select: { fullName: true, userId: true }
            }
          }
        }
      },
      orderBy: { submittedAt: 'desc' }
    })

    const formatted = proposals.map(p => ({
      id: p.id,
      bidAmount: p.proposedPrice,
      deliveryDays: p.deliveryTime,
      coverLetter: p.coverLetter,
      attachments: p.attachments,
      tokenCost: p.tokenCost,
      status: p.status,
      createdAt: p.submittedAt,
      updatedAt: p.updatedAt,
      project: {
        id: p.project.id,
        title: p.project.title,
        budget: p.project.budget,
        status: p.project.status,
        category: p.project.category,
        client: { name: p.project.clientProfile.fullName },
      }
    }))

    return res.status(200).json({
      success: true,
      proposals: formatted,
      tokenBalance: freelancerProfile.skillTokenBalance,
    })

  } catch (error) {
    console.error('Get my proposals error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────
// GET PROJECT PROPOSALS (Client view)
// GET /api/proposals/project/:projectId
// ─────────────────────────────────────────────────────────────
export const getProjectProposals = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { projectId } = req.params

    // Verify client owns this project
    const clientProfile = await prisma.clientProfile.findUnique({ where: { userId } })
    if (!clientProfile) {
      return res.status(404).json({ success: false, message: 'Client profile not found.' })
    }

    const project = await prisma.project.findUnique({ where: { id: projectId } })
    if (!project) {
      return res.status(404).json({ success: false, message: 'Project not found.' })
    }

    if (project.clientProfileId !== clientProfile.id) {
      return res.status(403).json({ success: false, message: 'Not authorized.' })
    }

    const proposals = await prisma.proposal.findMany({
      where: { projectId },
      include: {
        freelancerProfile: {
          include: {
            user: { select: { name: true, profileImage: true } },
            skills: { include: { skill: true }, take: 5 },
          }
        }
      },
      orderBy: { submittedAt: 'asc' }
    })

    const formatted = proposals.map(p => ({
      id: p.id,
      bidAmount: p.proposedPrice,
      deliveryDays: p.deliveryTime,
      coverLetter: p.coverLetter,
      attachments: p.attachments,
      tokenCost: p.tokenCost,
      status: p.status,
      createdAt: p.submittedAt,
      freelancer: {
        id: p.freelancerProfile.id,
        name: p.freelancerProfile.user?.name,
        profileImage: p.freelancerProfile.user?.profileImage,
        title: p.freelancerProfile.tagline,
        experienceLevel: p.freelancerProfile.experienceLevel,
        location: p.freelancerProfile.location,
        skills: p.freelancerProfile.skills.map(s => s.skill.name),
      }
    }))

    return res.status(200).json({ success: true, proposals: formatted })

  } catch (error) {
    console.error('Get project proposals error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────
// UPDATE PROPOSAL STATUS (Client: accept / reject / shortlist)
// PATCH /api/proposals/:id/status
// ─────────────────────────────────────────────────────────────
export const updateProposalStatus = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { id } = req.params
    const { status } = req.body

    const allowed = ['ACCEPTED', 'REJECTED', 'SHORTLISTED']
    if (!allowed.includes(status)) {
      return res.status(400).json({ success: false, message: `Status must be one of: ${allowed.join(', ')}` })
    }

    const clientProfile = await prisma.clientProfile.findUnique({ where: { userId } })
    if (!clientProfile) {
      return res.status(404).json({ success: false, message: 'Client profile not found.' })
    }

    const proposal = await prisma.proposal.findUnique({
      where: { id },
      include: {
        project: { select: { clientProfileId: true, title: true, id: true } },
        freelancerProfile: { select: { userId: true, id: true, skillTokenBalance: true } }
      }
    })

    if (!proposal) {
      return res.status(404).json({ success: false, message: 'Proposal not found.' })
    }

    if (proposal.project.clientProfileId !== clientProfile.id) {
      return res.status(403).json({ success: false, message: 'Not authorized.' })
    }

    if (status === 'ACCEPTED') {
      // Atomic: accept this, reject others, create contract
      await prisma.$transaction(async (tx) => {
        // Accept this proposal
        await tx.proposal.update({ where: { id }, data: { status: 'ACCEPTED' } })

        // Reject all other PENDING/SHORTLISTED proposals for this project
        await tx.proposal.updateMany({
          where: {
            projectId: proposal.projectId,
            id: { not: id },
            status: { in: ['PENDING', 'SHORTLISTED'] }
          },
          data: { status: 'REJECTED' }
        })

        // Update project status to IN_PROGRESS
        await tx.project.update({
          where: { id: proposal.projectId },
          data: { status: 'IN_PROGRESS' }
        })

        // Create contract
        await tx.contract.create({
          data: {
            projectId: proposal.projectId,
            freelancerProfileId: proposal.freelancerProfileId,
            agreedPrice: proposal.proposedPrice,
          }
        })

        // Notify the accepted freelancer
        await tx.notification.create({
          data: {
            userId: proposal.freelancerProfile.userId,
            type: 'PROPOSAL_ACCEPTED',
            title: '🎉 Your Proposal Was Accepted!',
            body: `Congratulations! Your proposal for "${proposal.project.title}" was accepted. A contract has been created.`,
            link: `/freelancer/proposals`,
          }
        })
      })

    } else if (status === 'SHORTLISTED') {
      await prisma.proposal.update({ where: { id }, data: { status: 'SHORTLISTED' } })

      // Notify freelancer
      await prisma.notification.create({
        data: {
          userId: proposal.freelancerProfile.userId,
          type: 'PROPOSAL_SHORTLISTED',
          title: '⭐ Your Proposal Was Shortlisted!',
          body: `Your proposal for "${proposal.project.title}" has been shortlisted. The client is reviewing it closely.`,
          link: `/freelancer/proposals`,
        }
      })

    } else {
      // REJECTED
      await prisma.proposal.update({ where: { id }, data: { status: 'REJECTED' } })

      await prisma.notification.create({
        data: {
          userId: proposal.freelancerProfile.userId,
          type: 'PROPOSAL_REJECTED',
          title: 'Proposal Update',
          body: `Your proposal for "${proposal.project.title}" was not selected this time. Keep applying!`,
          link: `/freelancer/proposals`,
        }
      })
    }

    return res.status(200).json({
      success: true,
      message: `Proposal ${status.toLowerCase()} successfully.`,
    })

  } catch (error) {
    console.error('Update proposal status error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────
// WITHDRAW PROPOSAL (Freelancer — refunds tokens)
// DELETE /api/proposals/:id/withdraw
// ─────────────────────────────────────────────────────────────
export const withdrawProposal = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId

    const freelancerProfile = await prisma.freelancerProfile.findUnique({
      where: { userId },
      select: { id: true, skillTokenBalance: true }
    })

    if (!freelancerProfile) {
      return res.status(404).json({ success: false, message: 'Freelancer profile not found.' })
    }

    const proposal = await prisma.proposal.findFirst({
      where: { id: req.params.id, freelancerProfileId: freelancerProfile.id },
      include: { project: { select: { title: true, clientProfile: { select: { userId: true } } } } }
    })

    if (!proposal) {
      return res.status(404).json({ success: false, message: 'Proposal not found.' })
    }

    if (!['PENDING', 'SHORTLISTED'].includes(proposal.status)) {
      return res.status(400).json({
        success: false,
        message: 'Only pending or shortlisted proposals can be withdrawn.'
      })
    }

    const refundAmount = proposal.tokenCost
    const newBalance = freelancerProfile.skillTokenBalance + refundAmount

    await prisma.$transaction(async (tx) => {
      // Mark as withdrawn
      await tx.proposal.update({ where: { id: proposal.id }, data: { status: 'WITHDRAWN' } })

      // Refund tokens
      await tx.freelancerProfile.update({
        where: { id: freelancerProfile.id },
        data: { skillTokenBalance: newBalance }
      })

      // Log refund transaction
      await tx.tokenTransaction.create({
        data: {
          freelancerProfileId: freelancerProfile.id,
          type: 'CREDIT',
          reason: 'PROPOSAL_WITHDRAWN',
          amount: refundAmount,
          balanceAfter: newBalance,
          description: `Refund for withdrawn proposal: ${proposal.project.title}`,
          relatedProposalId: proposal.id,
        }
      })

      // Decrement project proposal count
      await tx.project.update({
        where: { id: proposal.projectId },
        data: { proposalCount: { decrement: 1 } }
      })

      // Notify the client
      if (proposal.project.clientProfile?.userId) {
        await tx.notification.create({
          data: {
            userId: proposal.project.clientProfile.userId,
            type: 'PROPOSAL_WITHDRAWN',
            title: 'Proposal Withdrawn',
            body: `A freelancer has withdrawn their proposal for "${proposal.project.title}".`,
            link: `/client/projects/${proposal.projectId}/proposals`,
          }
        })
      }
    })

    return res.status(200).json({
      success: true,
      message: 'Proposal withdrawn successfully.',
      tokensRefunded: refundAmount,
      newBalance,
    })

  } catch (error) {
    console.error('Withdraw proposal error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}
