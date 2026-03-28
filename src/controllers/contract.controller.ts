import { Request, Response } from 'express'
import { prisma } from '../config/prisma'
import { uploadToCloudinary } from '../utils/uploadToCloudinary'
import { scheduleMilestoneAutoRelease } from '../queues/milestoneRelease.queue'
import { scheduleReviewAutoUnlock } from '../queues/reviewUnlock.queue'
import * as notificationService from '../services/notification.service'
import { updateClientStats } from '../services/tracking.service'

// ─────────────────────────────────────────────────────────────
// HELPER: Check if user has access to a contract
// ─────────────────────────────────────────────────────────────
async function resolveContractAccess(contractId: string, userId: string, role: 'CLIENT' | 'FREELANCER') {
  const contract = await prisma.contract.findUnique({
    where: { id: contractId },
    include: {
      milestones: { orderBy: { order: 'asc' } },
      payments: true,
      project: {
        include: {
          clientProfile: { select: { userId: true, fullName: true } },
        }
      },
      freelancerProfile: {
        include: {
          user: { select: { name: true, profileImage: true } }
        }
      }
    }
  })

  if (!contract) return null

  if (role === 'CLIENT') {
    if (contract.project.clientProfile.userId !== userId) return null
  } else {
    if (contract.freelancerProfile.userId !== userId) return null
  }

  return contract
}

// ─────────────────────────────────────────────────────────────
// GET ALL MY CONTRACTS (Client or Freelancer)
// GET /api/contracts
// ─────────────────────────────────────────────────────────────
export const getMyContracts = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const role = (req as any).user?.role

    let whereClause = {}
    if (role === 'CLIENT') {
      whereClause = { project: { clientProfile: { userId } } }
    } else {
      whereClause = { freelancerProfile: { userId } }
    }

    const contracts = await prisma.contract.findMany({
      where: whereClause,
      include: {
        project: { select: { title: true, budget: true, status: true } },
        freelancerProfile: { include: { user: { select: { name: true, profileImage: true } } } },
        milestones: { select: { status: true, amount: true } },
        payments: { select: { amount: true, status: true } },
      },
      orderBy: { createdAt: 'desc' }
    })

    const formatted = contracts.map(c => {
      const totalAmount = c.milestones.reduce((s, m) => s + m.amount, 0)
      const approvedAmount = c.milestones
        .filter(m => m.status === 'APPROVED')
        .reduce((s, m) => s + m.amount, 0)
      
      const escrowAmount = c.payments
        .filter((p: any) => p.status === 'HELD_IN_ESCROW')
        .reduce((sum: number, p: any) => sum + p.amount, 0)
      
      const progress = c.milestones.length > 0 
        ? (c.milestones.filter(m => m.status === 'APPROVED').length / c.milestones.length) * 100 
        : 0

      return {
        id: c.id,
        projectId: c.projectId,
        title: c.project.title,
        status: c.status,
        totalAmount,
        earnedAmount: approvedAmount,
        escrowAmount,
        progress: Math.round(progress),
        milestonesTotal: c.milestones.length,
        milestonesApproved: c.milestones.filter(m => m.status === 'APPROVED').length,
        milestonesSubmitted: c.milestones.filter(m => m.status === 'SUBMITTED').length,
        milestonesRevisionRequested: c.milestones.filter(m => m.status === 'REVISION_REQUESTED').length,
        createdAt: c.createdAt,
        freelancer: {
          name: c.freelancerProfile.user.name,
          image: c.freelancerProfile.user.profileImage
        }
      }
    })

    return res.status(200).json({ success: true, contracts: formatted })

  } catch (error) {
    console.error('Get my contracts error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────
// GET CONTRACT BY PROJECT ID
// GET /api/contracts/project/:projectId
// ─────────────────────────────────────────────────────────────
export const getContractByProject = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const userRole = (req as any).user?.role
    const { projectId } = req.params

    const contract = await prisma.contract.findUnique({
      where: { projectId },
      include: {
        milestones: { orderBy: { order: 'asc' } },
        payments: true,
        project: {
          include: {
            clientProfile: { select: { userId: true, fullName: true } },
          }
        },
        freelancerProfile: {
          include: {
            user: { select: { name: true, profileImage: true } }
          }
        }
      }
    })

    if (!contract) {
      return res.status(404).json({ success: false, message: 'Contract not found.' })
    }

    // Access check
    if (userRole === 'CLIENT' && contract.project.clientProfile.userId !== userId) {
      return res.status(403).json({ success: false, message: 'Not authorized.' })
    }
    if (userRole === 'FREELANCER' && contract.freelancerProfile.userId !== userId) {
      return res.status(403).json({ success: false, message: 'Not authorized.' })
    }

    return res.status(200).json({ success: true, contract: formatContract(contract) })
  } catch (error) {
    console.error('Get contract by project error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────
// GET CONTRACT BY CONTRACT ID
// GET /api/contracts/:contractId
// ─────────────────────────────────────────────────────────────
export const getContractById = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const userRole = (req as any).user?.role
    const { contractId } = req.params

    const contract = await prisma.contract.findUnique({
      where: { id: contractId },
      include: {
        milestones: { orderBy: { order: 'asc' } },
        payments: true,
        project: {
          include: {
            clientProfile: { select: { userId: true, fullName: true } },
          }
        },
        freelancerProfile: {
          include: {
            user: { select: { name: true, profileImage: true } }
          }
        }
      }
    })

    if (!contract) {
      return res.status(404).json({ success: false, message: 'Contract not found.' })
    }

    if (userRole === 'CLIENT' && contract.project.clientProfile.userId !== userId) {
      return res.status(403).json({ success: false, message: 'Not authorized.' })
    }
    if (userRole === 'FREELANCER' && contract.freelancerProfile.userId !== userId) {
      return res.status(403).json({ success: false, message: 'Not authorized.' })
    }

    return res.status(200).json({ success: true, contract: formatContract(contract) })
  } catch (error) {
    console.error('Get contract by id error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────
// SET / REPLACE CONTRACT MILESTONES (Client, before first fund)
// POST /api/contracts/:contractId/milestones
// ─────────────────────────────────────────────────────────────
export const setContractMilestones = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { contractId } = req.params
    const { milestones } = req.body

    if (!Array.isArray(milestones) || milestones.length === 0) {
      return res.status(400).json({ success: false, message: 'At least one milestone is required.' })
    }

    const contract = await resolveContractAccess(contractId, userId, 'CLIENT')
    if (!contract) {
      return res.status(404).json({ success: false, message: 'Contract not found or not authorized.' })
    }

    // Ensure no milestone is already FUNDED/IN_PROGRESS/SUBMITTED/APPROVED
    const hasFunded = contract.milestones.some((m: any) =>
      ['FUNDED', 'IN_PROGRESS', 'SUBMITTED', 'APPROVED'].includes(m.status)
    )
    if (hasFunded) {
      return res.status(400).json({ success: false, message: 'Cannot modify milestones once work has started.' })
    }

    // Replace all milestones atomically
    await prisma.$transaction(async (tx) => {
      // Delete existing milestones
      await tx.milestone.deleteMany({ where: { contractId } })

      // Re-create
      for (let i = 0; i < milestones.length; i++) {
        const m = milestones[i]
        await tx.milestone.create({
          data: {
            contractId,
            order: i,
            title: m.title,
            description: m.description || null,
            amount: Number(m.amount),
            dueDate: m.dueDate ? new Date(m.dueDate) : null,
            status: 'PENDING',
            attachments: [],
          }
        })
      }

      // Update contract agreedPrice to sum of milestones
      const total = milestones.reduce((sum: number, m: any) => sum + Number(m.amount), 0)
      await tx.contract.update({
        where: { id: contractId },
        data: { agreedPrice: total }
      })
    })

    // Fetch updated contract
    const updated = await prisma.contract.findUnique({
      where: { id: contractId },
      include: { milestones: { orderBy: { order: 'asc' } }, payments: true }
    })

    return res.status(200).json({ success: true, message: 'Milestones updated.', contract: updated })
  } catch (error) {
    console.error('Set milestones error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────
// FUND A MILESTONE (Client — dummy escrow)
// POST /api/contracts/:contractId/milestones/:milestoneId/fund
// ─────────────────────────────────────────────────────────────
export const fundMilestone = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { contractId, milestoneId } = req.params

    const contract = await resolveContractAccess(contractId, userId, 'CLIENT')
    if (!contract) {
      return res.status(404).json({ success: false, message: 'Contract not found or not authorized.' })
    }

    const milestone = contract.milestones.find((m: any) => m.id === milestoneId)
    if (!milestone) {
      return res.status(404).json({ success: false, message: 'Milestone not found.' })
    }

    if (milestone.status !== 'PENDING') {
      return res.status(400).json({ success: false, message: `Milestone cannot be funded in "${milestone.status}" status.` })
    }

    // Only allow funding if it's the next unfunded milestone
    // (milestones must be funded in order)
    const pendingBefore = contract.milestones.filter(
      (m: any) => m.order < milestone.order && m.status === 'PENDING'
    )
    if (pendingBefore.length > 0) {
      return res.status(400).json({ success: false, message: 'Please fund milestones in order.' })
    }

    await prisma.$transaction(async (tx) => {
      // Mark milestone as FUNDED → IN_PROGRESS (work can start)
      await tx.milestone.update({
        where: { id: milestoneId },
        data: { 
          status: 'FUNDED',
          history: [
            {
              type: 'FUNDED',
              timestamp: new Date(),
              content: `Milestone funded. $${milestone.amount.toLocaleString()} is now held in escrow.`,
              actorName: contract.project.clientProfile.fullName,
              actorRole: 'CLIENT'
            }
          ]
        }
      })

      // Create a payment record (dummy — HELD_IN_ESCROW)
      await tx.payment.create({
        data: {
          contractId,
          milestoneId,
          amount: milestone.amount,
          status: 'HELD_IN_ESCROW',
          transactionId: `DUMMY_${Date.now()}`,
        }
      })

      // Notify freelancer
      await notificationService.createNotification({
        userId: contract.freelancerProfile.userId,
        type: 'PAYMENT_RELEASED',
        title: 'Milestone Funded!',
        body: `Client has funded "${milestone.title}" — $${milestone.amount.toFixed(2)} is now in escrow. You can start work!`,
        link: `/freelancer/contracts/${contractId}`,
      }, tx)
    })

    return res.status(200).json({ success: true, message: 'Milestone funded successfully. Freelancer can now start work.' })
  } catch (error) {
    console.error('Fund milestone error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────
// START MILESTONE (Freelancer — marks IN_PROGRESS)
// POST /api/contracts/:contractId/milestones/:milestoneId/start
// ─────────────────────────────────────────────────────────────
export const startMilestone = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { contractId, milestoneId } = req.params

    const contract = await resolveContractAccess(contractId, userId, 'FREELANCER')
    if (!contract) {
      return res.status(404).json({ success: false, message: 'Contract not found or not authorized.' })
    }

    const milestone = contract.milestones.find((m: any) => m.id === milestoneId)
    if (!milestone) {
      return res.status(404).json({ success: false, message: 'Milestone not found.' })
    }

    if (milestone.status !== 'FUNDED') {
      return res.status(400).json({ success: false, message: 'Milestone must be funded before starting.' })
    }

    await prisma.$transaction(async (tx) => {
      // Fetch latest history
      const milestone = await tx.milestone.findUnique({
        where: { id: milestoneId },
        select: { history: true }
      })
      const currentHistory = Array.isArray(milestone?.history) ? milestone.history : []

      await tx.milestone.update({
        where: { id: milestoneId },
        data: { 
          status: 'IN_PROGRESS',
          history: [
            ...currentHistory,
            {
              type: 'STARTED',
              timestamp: new Date(),
              content: 'Freelancer started working on this milestone.',
              actorName: contract.freelancerProfile.user?.name,
              actorRole: 'FREELANCER'
            }
          ]
        }
      })
    })

    return res.status(200).json({ success: true, message: 'Milestone started.' })
  } catch (error) {
    console.error('Start milestone error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────
// SUBMIT MILESTONE DELIVERABLES (Freelancer)
// POST /api/contracts/:contractId/milestones/:milestoneId/submit
// ─────────────────────────────────────────────────────────────
export const submitMilestone = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { contractId, milestoneId } = req.params
    const { deliverables } = req.body

    const contract = await resolveContractAccess(contractId, userId, 'FREELANCER')
    if (!contract) {
      return res.status(404).json({ success: false, message: 'Contract not found or not authorized.' })
    }

    const milestone = contract.milestones.find((m: any) => m.id === milestoneId)
    if (!milestone) {
      return res.status(404).json({ success: false, message: 'Milestone not found.' })
    }

    if (!['FUNDED', 'IN_PROGRESS', 'REVISION_REQUESTED'].includes(milestone.status)) {
      return res.status(400).json({
        success: false,
        message: `Cannot submit milestone with status "${milestone.status}".`
      })
    }

    // Handle uploaded attachments — only the new files uploaded in this submission
    const newAttachmentUrls: string[] = []
    if (req.files && Array.isArray(req.files)) {
      for (const file of req.files as Express.Multer.File[]) {
        const url = await uploadToCloudinary(file.buffer, file.originalname, file.mimetype)
        newAttachmentUrls.push(url)
      }
    }

    // Full accumulated list for the milestone record
    const allAttachments: string[] = [...(milestone.attachments || []), ...newAttachmentUrls]

    await prisma.$transaction(async (tx) => {
      // Fetch latest history to prevent race conditions
      const latestMilestone = await tx.milestone.findUnique({
        where: { id: milestoneId },
        select: { history: true }
      })
      const currentHistory = Array.isArray(latestMilestone?.history) ? latestMilestone.history : []

      await tx.milestone.update({
        where: { id: milestoneId },
        data: {
          status: 'SUBMITTED',
          deliverables: deliverables || null,
          submittedAt: new Date(),
          attachments: allAttachments,
          history: [
            ...currentHistory,
            {
              type: 'SUBMISSION',
              timestamp: new Date(),
              content: deliverables || 'Milestone submitted for review.',
              // Only record the files attached to THIS submission
              attachments: newAttachmentUrls,
              actorName: contract.freelancerProfile.user?.name,
              actorRole: 'FREELANCER'
            }
          ]
        }
      })

      // Notify client
      await notificationService.createNotification({
        userId: contract.project.clientProfile.userId,
        type: 'MILESTONE_SUBMITTED',
        title: 'Milestone Submitted!',
        body: `Freelancer has submitted deliverables for "${milestone.title}". Please review within 3 days; otherwise, payment will be automatically released.`,
        link: `/client/contracts/${contractId}`,
      }, tx)
    })

    // ── Schedule 72-hour auto-release job ──────────────────────
    // If the client doesn't act within 72h, payment is auto-released.
    // Guard checks inside the job prevent double-release.
    await scheduleMilestoneAutoRelease(milestoneId, contractId)

    return res.status(200).json({ success: true, message: 'Milestone submitted for review.' })
  } catch (error) {
    console.error('Submit milestone error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────
// APPROVE MILESTONE (Client — releases payment)
// POST /api/contracts/:contractId/milestones/:milestoneId/approve
// ─────────────────────────────────────────────────────────────
export const approveMilestone = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { contractId, milestoneId } = req.params

    const contract = await resolveContractAccess(contractId, userId, 'CLIENT')
    if (!contract) {
      return res.status(404).json({ success: false, message: 'Contract not found or not authorized.' })
    }

    const milestone = contract.milestones.find((m: any) => m.id === milestoneId)
    if (!milestone) {
      return res.status(404).json({ success: false, message: 'Milestone not found.' })
    }

    if (milestone.status !== 'SUBMITTED') {
      return res.status(400).json({ success: false, message: 'Can only approve a submitted milestone.' })
    }

    await prisma.$transaction(async (tx) => {
      // Fetch latest history
      const latestMilestone = await tx.milestone.findUnique({
        where: { id: milestoneId },
        select: { history: true }
      })
      const currentHistory = Array.isArray(latestMilestone?.history) ? latestMilestone.history : []

      // Mark milestone approved
      await tx.milestone.update({
        where: { id: milestoneId },
        data: { 
          status: 'APPROVED', 
          approvedAt: new Date(),
          history: [
            ...currentHistory,
            {
              type: 'APPROVAL',
              timestamp: new Date(),
              content: 'Milestone approved and payment released.',
              actorName: contract.project.clientProfile.fullName,
              actorRole: 'CLIENT'
            }
          ]
        }
      })

      // Release payment (dummy)
      await tx.payment.updateMany({
        where: { milestoneId, status: 'HELD_IN_ESCROW' },
        data: { status: 'RELEASED', releasedAt: new Date() }
      })

      // Notify freelancer
      await notificationService.createNotification({
        userId: contract.freelancerProfile.userId,
        type: 'MILESTONE_APPROVED',
        title: 'Milestone Approved!',
        body: `"${milestone.title}" was approved! $${milestone.amount.toFixed(2)} has been released to you.`,
        link: `/freelancer/contracts/${contractId}`,
      }, tx)

      // Check if all milestones approved → complete contract
      const totalMilestones = contract.milestones.length
      const approvedCount = contract.milestones.filter((m: any) =>
        m.id === milestoneId ? true : m.status === 'APPROVED'
      ).length

      if (approvedCount === totalMilestones) {
        await tx.contract.update({
          where: { id: contractId },
          data: { status: 'COMPLETED', endDate: new Date() }
        })
        await tx.project.update({
          where: { id: contract.project.id },
          data: { status: 'COMPLETED' }
        })

        // Notify both parties: contract complete + leave a review CTA
        await notificationService.createNotification({
          userId: contract.freelancerProfile.userId,
          type: 'MILESTONE_APPROVED',
          title: 'Contract Completed!',
          body: `All milestones approved for "${contract.project.title}". Leave a review for your client — you have 7 days.`,
          link: `/freelancer/contracts/${contractId}`,
        }, tx)
        await notificationService.createNotification({
          userId: contract.project.clientProfile.userId,
          type: 'MILESTONE_APPROVED',
          title: 'Contract Completed!',
          body: `All milestones approved for "${contract.project.title}". Leave a review for your freelancer — you have 7 days.`,
          link: `/client/contracts/${contractId}`,
        }, tx)
      }
    })

    // Schedule 7-day review auto-unlock job (outside transaction — queue operation)
    const finalMilestones = await prisma.milestone.findMany({ where: { contractId } })
    const allApproved = finalMilestones.every((m: any) =>
      m.id === milestoneId ? true : m.status === 'APPROVED'
    )
    if (allApproved) {
      await scheduleReviewAutoUnlock(contractId)
    }

    return res.status(200).json({ success: true, message: 'Milestone approved and payment released!' })
  } catch (error) {
    console.error('Approve milestone error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────
// REQUEST REVISION (Client)
// POST /api/contracts/:contractId/milestones/:milestoneId/revision
// ─────────────────────────────────────────────────────────────
export const requestRevision = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { contractId, milestoneId } = req.params
    const { note } = req.body

    const contract = await resolveContractAccess(contractId, userId, 'CLIENT')
    if (!contract) {
      return res.status(404).json({ success: false, message: 'Contract not found or not authorized.' })
    }

    const milestone = contract.milestones.find((m: any) => m.id === milestoneId)
    if (!milestone) {
      return res.status(404).json({ success: false, message: 'Milestone not found.' })
    }

    if (milestone.status !== 'SUBMITTED') {
      return res.status(400).json({ success: false, message: 'Revision can only be requested on submitted milestones.' })
    }

    // Enforce revision limit
    if (milestone.allowedRevisions !== -1 && milestone.revisionsUsed >= milestone.allowedRevisions) {
      return res.status(400).json({ 
        success: false, 
        message: `Revision limit reached (${milestone.allowedRevisions}/${milestone.allowedRevisions}). No more revisions allowed for this milestone.` 
      })
    }

    await prisma.$transaction(async (tx) => {
      // Fetch latest history
      const latestMilestone = await tx.milestone.findUnique({
        where: { id: milestoneId },
        select: { history: true }
      })
      const currentHistory = Array.isArray(latestMilestone?.history) ? latestMilestone.history : []

      await tx.milestone.update({
        where: { id: milestoneId },
        data: {
          status: 'REVISION_REQUESTED',
          revisionNote: note || 'Client has requested revisions.',
          submittedAt: null,
          revisionsUsed: { increment: 1 },
          history: [
            ...currentHistory,
            {
              type: 'REVISION_REQUEST',
              timestamp: new Date(),
              content: note || 'Client requested revisions.',
              actorName: contract.project.clientProfile.fullName,
              actorRole: 'CLIENT'
            }
          ]
        }
      })

      await notificationService.createNotification({
        userId: contract.freelancerProfile.userId,
        type: 'MILESTONE_SUBMITTED', // Or maybe define REVISION_REQUESTED? MILESTONE_SUBMITTED is used here in original
        title: 'Revision Requested',
        body: `Client requested revisions for "${milestone.title}": ${note || 'Please review and resubmit.'}`,
        link: `/freelancer/contracts/${contractId}`,
      }, tx)
    })

    return res.status(200).json({ success: true, message: 'Revision requested.' })
  } catch (error) {
    console.error('Request revision error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────
// APPROVE CONTRACT OFFER (Freelancer — for modified milestones)
// PATCH /api/contracts/:contractId/approve
// ─────────────────────────────────────────────────────────────
export const approveContractOffer = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { contractId } = req.params

    const contract = await resolveContractAccess(contractId, userId, 'FREELANCER')
    if (!contract) {
      return res.status(404).json({ success: false, message: 'Contract not found or not authorized.' })
    }

    if (contract.status !== 'OFFER_PENDING') {
      return res.status(400).json({ success: false, message: 'Contract is not in a pending approval state.' })
    }

    await prisma.$transaction(async (tx) => {
      // 1. Update contract status to ACTIVE
      await tx.contract.update({
        where: { id: contractId },
        data: { status: 'ACTIVE' }
      })

      // Update client hire stats
      await updateClientStats(tx, contract.project.clientProfileId)

      // 2. Update project status to IN_PROGRESS
      await tx.project.update({
        where: { id: contract.projectId },
        data: { status: 'IN_PROGRESS' }
      })

      // 3. Notify the client
      await notificationService.createNotification({
        userId: contract.project.clientProfile.userId,
        type: 'PROJECT_STARTED',
        title: 'Your contract was approved!',
        body: `Freelancer has approved the milestones for "${contract.project.title}". Work can now begin.`,
        link: `/client/contracts/${contractId}`,
      }, tx)
    })

    return res.status(200).json({ success: true, message: 'Contract approved! Work can now begin.' })
  } catch (error) {
    console.error('Approve contract offer error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────
// HELPER: Format contract for response
// ─────────────────────────────────────────────────────────────
function formatContract(contract: any) {
  const totalMilestoneAmount = contract.milestones.reduce(
    (sum: number, m: any) => sum + m.amount, 0
  )
  const releasedAmount = contract.payments
    .filter((p: any) => p.status === 'RELEASED')
    .reduce((sum: number, p: any) => sum + p.amount, 0)
  const escrowAmount = contract.payments
    .filter((p: any) => p.status === 'HELD_IN_ESCROW')
    .reduce((sum: number, p: any) => sum + p.amount, 0)

  return {
    id: contract.id,
    projectId: contract.project.id,
    projectTitle: contract.project.title,
    clientName: contract.project.clientProfile.fullName,
    freelancerName: contract.freelancerProfile.user?.name,
    freelancerImage: contract.freelancerProfile.user?.profileImage,
    agreedPrice: contract.agreedPrice,
    status: contract.status,
    startDate: contract.startDate,
    endDate: contract.endDate,
    milestonesModifiedByClient: contract.milestonesModifiedByClient ?? false,
    milestones: contract.milestones.map((m: any) => ({
      ...m,
      history: Array.isArray(m.history) ? m.history : []
    })),
    totalMilestoneAmount,
    releasedAmount,
    escrowAmount,
    pendingAmount: totalMilestoneAmount - releasedAmount - escrowAmount,
  }
}

// ─────────────────────────────────────────────────────────────
// REJECT CONTRACT OFFER (Freelancer — for modified milestones)
// DELETE /api/contracts/:contractId/reject
// ─────────────────────────────────────────────────────────────
export const rejectContractOffer = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { contractId } = req.params

    const contract = await resolveContractAccess(contractId, userId, 'FREELANCER')
    if (!contract) {
      return res.status(404).json({ success: false, message: 'Contract not found or not authorized.' })
    }

    if (contract.status !== 'OFFER_PENDING') {
      return res.status(400).json({ success: false, message: 'Contract is not in a pending approval state.' })
    }

    await prisma.$transaction(async (tx) => {
      // 1. Delete the contract offer
      await tx.contract.delete({
        where: { id: contractId }
      })

      // 2. Set project status back to OPEN
      await tx.project.update({
        where: { id: contract.projectId },
        data: { status: 'OPEN' }
      })

      // 3. Set the proposal status back to PENDING
      await tx.proposal.update({
        where: { 
          projectId_freelancerProfileId: {
            projectId: contract.projectId,
            freelancerProfileId: contract.freelancerProfileId
          }
        },
        data: { status: 'PENDING' }
      })

      // 4. Notify the client
      await notificationService.createNotification({
        userId: contract.project.clientProfile.userId,
        type: 'PROJECT_STARTED', // Re-using for simplicity or define OFFER_REJECTED
        title: 'Contract offer rejected',
        body: `Freelancer has rejected your modified milestone plan for "${contract.project.title}". The project is back to OPEN.`,
        link: `/client/proposals/project/${contract.projectId}`,
      }, tx)
    })

    return res.status(200).json({ success: true, message: 'Offer rejected. Project is back to OPEN.' })
  } catch (error) {
    console.error('Reject contract offer error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}
