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
    const { bidAmount, deliveryDays, coverLetter, milestones, generalRevisionLimit } = req.body

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
          proposalMilestones: milestones ? JSON.parse(typeof milestones === 'string' ? milestones : JSON.stringify(milestones)) : null,
          generalRevisionLimit: generalRevisionLimit ? Number(generalRevisionLimit) : 3,
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
            },
            contract: { select: { id: true, createdAt: true } }
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
      proposalMilestones: p.proposalMilestones || null,
      clientRequestedMilestones: p.clientRequestedMilestones || null,
      negotiationStatus: p.negotiationStatus || null,
      generalRevisionLimit: p.generalRevisionLimit || null,
      createdAt: p.submittedAt,
      updatedAt: p.updatedAt,
      contract: p.project.contract,
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
        },
        project: {
          include: { contract: { select: { id: true, createdAt: true } } }
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
      proposalMilestones: p.proposalMilestones || null,
      clientRequestedMilestones: p.clientRequestedMilestones || null,
      negotiationStatus: p.negotiationStatus || null,
      generalRevisionLimit: p.generalRevisionLimit || null,
      createdAt: p.submittedAt,
      contract: p.project?.contract || null,
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

        // ── Check if milestones were negotiated or modified ──
        const { clientMilestones } = req.body
        const proposalMilestones = proposal.proposalMilestones as any[] | null
        const requestedMilestones = proposal.clientRequestedMilestones as any[] | null
        
        // Priority: 1. Direct body (for backward compat), 2. Negotiated (accepted), 3. Original
        let rawMilestones: any[] = []
        let milestonesModifiedByClient = false

        if (clientMilestones) {
          rawMilestones = typeof clientMilestones === 'string' ? JSON.parse(clientMilestones) : clientMilestones
          milestonesModifiedByClient = true 
        } else if (proposal.negotiationStatus === 'FREELANCER_ACCEPTED' && requestedMilestones) {
          rawMilestones = requestedMilestones
          milestonesModifiedByClient = false // It's accepted, so it becomes the ACTIVE plan
        } else {
          rawMilestones = proposalMilestones || []
        }

        // If it was proposed but NOT yet accepted, it's still an OFFER_PENDING situation if hired now
        if (proposal.negotiationStatus === 'CLIENT_PROPOSED' && !clientMilestones) {
          rawMilestones = requestedMilestones || []
          milestonesModifiedByClient = true
        }

        const contractStatus = milestonesModifiedByClient ? 'OFFER_PENDING' : 'ACTIVE'
        const projectStatus = milestonesModifiedByClient ? 'HIRED_PENDING' : 'IN_PROGRESS'

        // Update project status
        await tx.project.update({
          where: { id: proposal.projectId },
          data: { status: projectStatus }
        })



        // Create contract
        const contract = await tx.contract.create({
          data: {
            projectId: proposal.projectId,
            freelancerProfileId: proposal.freelancerProfileId,
            agreedPrice: rawMilestones.length > 0
              ? rawMilestones.reduce((s: number, m: any) => s + Number(m.amount), 0)
              : proposal.proposedPrice,
            status: contractStatus,
            milestonesModifiedByClient,
          }
        })

        // Create milestone records if provided
        if (rawMilestones.length > 0) {
          for (let i = 0; i < rawMilestones.length; i++) {
            const m = rawMilestones[i]
            await tx.milestone.create({
              data: {
                contractId: contract.id,
                order: i,
                title: m.title,
                description: m.description || null,
                amount: Number(m.amount),
                dueDate: m.dueDate ? new Date(m.dueDate) : null,
                status: 'PENDING',
                allowedRevisions: m.allowedRevisions !== undefined ? Number(m.allowedRevisions) : 3,
                attachments: [],
              }
            })
          }
        }

        // Notify the accepted freelancer
        const notificationTitle = milestonesModifiedByClient 
          ? '🎁 You have a new contract offer!' 
          : '🎉 Your Proposal Was Accepted!'
        const notificationBody = milestonesModifiedByClient
          ? `Client hired you for "${proposal.project.title}" but modified the milestones. Review and approve to start work.`
          : `Congratulations! Your proposal for "${proposal.project.title}" was accepted. A contract has been created.`

        await tx.notification.create({
          data: {
            userId: proposal.freelancerProfile.userId,
            type: 'PROPOSAL_ACCEPTED',
            title: notificationTitle,
            body: notificationBody,
            link: `/freelancer/contracts/${contract.id}`,
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
            type: 'SYSTEM_ALERT',
            title: 'Proposal Withdrawn',
            body: `A freelancer has withdrawn their proposal for "${(proposal as any).project?.title || 'the project'}".`,
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

// ─────────────────────────────────────────────────────────────
// PROPOSE MILESTONE CHANGES (Client)
// POST /api/proposals/:proposalId/negotiate
// ─────────────────────────────────────────────────────────────
export const proposeMilestoneChanges = async (req: Request, res: Response): Promise<any> => {
  try {
    const userId = (req as any).user?.userId
    const id = req.params.id as string
    const { milestones } = req.body

    const proposal = await prisma.proposal.findUnique({
      where: { id },
      include: {
        project: {
          include: { clientProfile: { select: { userId: true } } }
        }
      }
    })

    if (!proposal || (proposal as any).project?.clientProfile?.userId !== userId) {
      return res.status(404).json({ success: false, message: 'Proposal not found or access denied.' })
    }

    await prisma.proposal.update({
      where: { id },
      data: {
        clientRequestedMilestones: milestones,
        negotiationStatus: 'CLIENT_PROPOSED'
      }
    })

    // I need to fetch the freelancer's userId first.
    
    const freelancer = await prisma.freelancerProfile.findUnique({
      where: { id: proposal.freelancerProfileId },
      select: { userId: true }
    })

    if (freelancer) {
      await prisma.notification.create({
        data: {
          userId: freelancer.userId,
          type: 'SYSTEM_ALERT',
          title: '🤝 Milestone Changes Proposed',
          body: `Client has proposed changes to your milestone plan for "${(proposal as any).project?.title || 'the project'}". Please review and accept to move forward.`,
          link: `/freelancer/proposals/${id}`,
        }
      })
    }

    return res.status(200).json({ success: true, message: 'Changes proposed to freelancer.' })
  } catch (error) {
    console.error('Propose changes error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────
// ACCEPT MILESTONE CHANGES (Freelancer)
// POST /api/proposals/:proposalId/accept-changes
// ─────────────────────────────────────────────────────────────
export const acceptMilestoneChanges = async (req: Request, res: Response): Promise<any> => {
  try {
    const userId = (req as any).user?.userId
    const id = req.params.id as string

    const proposal = await prisma.proposal.findUnique({
      where: { id },
      include: {
        freelancerProfile: { select: { userId: true } },
        project: { include: { clientProfile: { select: { userId: true } } } }
      }
    })

    if (!proposal || (proposal as any).freelancerProfile?.userId !== userId) {
      return res.status(404).json({ success: false, message: 'Proposal not found or access denied.' })
    }

    await prisma.proposal.update({
      where: { id },
      data: { negotiationStatus: 'FREELANCER_ACCEPTED' }
    })

    // Notify client
    await prisma.notification.create({
      data: {
        userId: (proposal as any).project?.clientProfile?.userId,
        type: 'SYSTEM_ALERT',
        title: '✅ Milestone Changes Accepted!',
        body: `Freelancer has accepted your proposed milestone plan for "${(proposal as any).project?.title || 'the project'}". You can now finalize the hire.`,
        link: `/client/projects/${proposal.projectId}/proposals`,
      }
    })

    return res.status(200).json({ success: true, message: 'Changes accepted. Client has been notified.' })
  } catch (error) {
    console.error('Accept changes error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}
