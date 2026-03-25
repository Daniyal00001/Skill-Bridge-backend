import { Request, Response } from 'express'
import { prisma } from '../config/prisma'

/**
 * @desc    Get all invitations for the authenticated user (Client or Freelancer)
 * @route   GET /api/invitations
 * @access  Private
 */
export const getInvitations = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const role = (req as any).user?.role

    let whereClause = {}
    if (role === 'CLIENT') {
      const clientProfile = await prisma.clientProfile.findUnique({ where: { userId } })
      if (!clientProfile) return res.status(404).json({ success: false, message: 'Client profile not found' })
      whereClause = { clientProfileId: clientProfile.id }
    } else if (role === 'FREELANCER') {
      const freelancerProfile = await prisma.freelancerProfile.findUnique({ where: { userId } })
      if (!freelancerProfile) return res.status(404).json({ success: false, message: 'Freelancer profile not found' })
      whereClause = { freelancerProfileId: freelancerProfile.id }
    } else {
      return res.status(403).json({ success: false, message: 'Not authorized' })
    }

    const invitations = await prisma.invitation.findMany({
      where: whereClause,
      orderBy: { createdAt: 'desc' }
    })

    // Manual joins to handle potential orphaned records without crashing
    const projectIds = [...new Set(invitations.map(i => i.projectId))]
    const freelancerIds = [...new Set(invitations.map(i => i.freelancerProfileId))]
    const clientIds = [...new Set(invitations.map(i => i.clientProfileId))]

    const [projects, freelancers, clients] = await Promise.all([
      prisma.project.findMany({
        where: { id: { in: projectIds } },
        select: { id: true, title: true, budget: true, budgetType: true }
      }),
      prisma.freelancerProfile.findMany({
        where: { id: { in: freelancerIds } },
        include: { user: { select: { name: true, profileImage: true } } }
      }),
      prisma.clientProfile.findMany({
        where: { id: { in: clientIds } },
        include: { user: { select: { name: true, profileImage: true } } }
      })
    ])

    const projectMap = new Map(projects.map(p => [p.id, p]))
    const freelancerMap = new Map(freelancers.map(f => [f.id, f]))
    const clientMap = new Map(clients.map(c => [c.id, c]))

    const formatted = invitations
      .map(inv => {
        const project = projectMap.get(inv.projectId)
        const freelancer = freelancerMap.get(inv.freelancerProfileId)
        const client = clientMap.get(inv.clientProfileId)

        // Profiles are critical, but we can handle missing projects gracefully
        if (!freelancer || !client) return null

        return {
          id: inv.id,
          projectId: inv.projectId,
          projectTitle: project?.title || 'Project Deleted',
          projectBudget: project?.budget || 0,
          projectBudgetType: project?.budgetType || 'FIXED',
          freelancerId: inv.freelancerProfileId,
          freelancerName: freelancer.user?.name || 'Unknown Freelancer',
          freelancerAvatar: freelancer.user?.profileImage,
          clientId: inv.clientProfileId,
          clientName: client.user?.name || 'Unknown Client',
          clientAvatar: client.user?.profileImage,
          message: inv.message,
          status: project ? inv.status : 'CANCELLED', // Mark as cancelled if project is gone
          milestones: inv.milestones,
          revisionsAllowed: inv.revisionsAllowed,
          budget: inv.budget,
          attachments: inv.attachments,
          createdAt: inv.createdAt
        }
      })
      .filter(Boolean)

    return res.status(200).json({ success: true, data: formatted })
  } catch (error) {
    console.error('Get invitations error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error' })
  }
}

/**
 * @desc    Client cancels a pending invitation
 * @route   PATCH /api/invitations/:id/cancel
 * @access  Private (CLIENT)
 */
export const cancelInvitation = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { id } = req.params

    const clientProfile = await prisma.clientProfile.findUnique({ where: { userId } })
    if (!clientProfile) return res.status(404).json({ success: false, message: 'Client profile not found' })

    const invitation = await prisma.invitation.findUnique({ where: { id } })
    if (!invitation || invitation.clientProfileId !== clientProfile.id) {
      return res.status(404).json({ success: false, message: 'Invitation not found or unauthorized' })
    }

    if (invitation.status !== 'PENDING') {
      return res.status(400).json({ success: false, message: `Cannot cancel an invitation with status ${invitation.status}` })
    }

    const updated = await prisma.invitation.update({
      where: { id },
      data: { status: 'CANCELLED' }
    })

    return res.status(200).json({ success: true, data: updated, message: 'Invitation cancelled successfully' })
  } catch (error) {
    console.error('Cancel invitation error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error' })
  }
}

/**
 * @desc    Freelancer accepts an invitation (Converts to active contract)
 * @route   PATCH /api/invitations/:id/accept
 * @access  Private (FREELANCER)
 */
export const acceptInvitation = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { id } = req.params

    const freelancerProfile = await prisma.freelancerProfile.findUnique({ where: { userId } })
    if (!freelancerProfile) return res.status(404).json({ success: false, message: 'Freelancer profile not found' })

    const invitation = await prisma.invitation.findUnique({
      where: { id },
      include: {
        project: { select: { title: true, clientProfile: { select: { userId: true } } } }
      }
    })

    if (!invitation || invitation.freelancerProfileId !== freelancerProfile.id) {
      return res.status(404).json({ success: false, message: 'Invitation not found or unauthorized' })
    }

    if (invitation.status !== 'PENDING') {
      return res.status(400).json({ success: false, message: `Cannot accept an invitation with status ${invitation.status}` })
    }

    const result = await prisma.$transaction(async (tx) => {
      // 1. Mark this invite as ACCEPTED
      const updatedInvite = await tx.invitation.update({
        where: { id },
        data: { status: 'ACCEPTED' }
      })

      // 2. Reject all other PENDING invitations for this project
      await tx.invitation.updateMany({
        where: { projectId: invitation.projectId, id: { not: id }, status: 'PENDING' },
        data: { status: 'CANCELLED' } // or REJECTED
      })

      // 3. Reject all pending PROPOSALS for this project
      await tx.proposal.updateMany({
        where: { projectId: invitation.projectId, status: { in: ['PENDING', 'SHORTLISTED'] } },
        data: { status: 'REJECTED' }
      })

      // 4. Create Contract
      const rawMilestones = (invitation.milestones as any[]) || []
      const contract = await tx.contract.create({
        data: {
          projectId: invitation.projectId,
          freelancerProfileId: invitation.freelancerProfileId,
          agreedPrice: invitation.budget || rawMilestones.reduce((sum, m) => sum + Number(m.amount), 0),
          status: 'ACTIVE',
          milestonesModifiedByClient: false
        }
      })

      // 5. Create Milestones
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
              allowedRevisions: m.revisionsAllowed !== undefined ? Number(m.revisionsAllowed) : invitation.revisionsAllowed,
              attachments: []
            }
          })
        }
      } else {
         // Create default deliverable
         await tx.milestone.create({
           data: {
             contractId: contract.id,
             order: 0,
             title: 'Full Project Deliverable',
             description: 'Complete the project as described.',
             amount: contract.agreedPrice,
             status: 'PENDING',
             allowedRevisions: invitation.revisionsAllowed,
             attachments: []
           }
         })
      }

      // 6. Update Project Status
      await tx.project.update({
        where: { id: invitation.projectId },
        data: { status: 'IN_PROGRESS' }
      })

      // 7. Notify Client
      await tx.notification.create({
        data: {
          userId: invitation.project.clientProfile.userId,
          type: 'SYSTEM_ALERT',
          title: '🎉 Invitation Accepted!',
          body: `Freelancer accepted your invitation for "${invitation.project.title}". A contract has been created.`,
          link: `/client/contracts/${contract.id}`
        }
      })

      return contract
    })

    return res.status(200).json({ success: true, message: 'Invitation accepted and contract created.', contractId: result.id })
  } catch (error) {
    console.error('Accept invitation error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error' })
  }
}

/**
 * @desc    Freelancer rejects an invitation
 * @route   PATCH /api/invitations/:id/reject
 * @access  Private (FREELANCER)
 */
export const rejectInvitation = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { id } = req.params

    const freelancerProfile = await prisma.freelancerProfile.findUnique({ where: { userId } })
    if (!freelancerProfile) return res.status(404).json({ success: false, message: 'Freelancer profile not found' })

    const invitation = await prisma.invitation.findUnique({
      where: { id },
      include: {
        project: { select: { title: true, clientProfile: { select: { userId: true } } } }
      }
    })

    if (!invitation || invitation.freelancerProfileId !== freelancerProfile.id) {
      return res.status(404).json({ success: false, message: 'Invitation not found or unauthorized' })
    }

    if (invitation.status !== 'PENDING') {
      return res.status(400).json({ success: false, message: `Cannot reject an invitation with status ${invitation.status}` })
    }

    const updated = await prisma.$transaction(async (tx) => {
      const inv = await tx.invitation.update({
        where: { id },
        data: { status: 'REJECTED' }
      })

      await tx.notification.create({
        data: {
          userId: invitation.project.clientProfile.userId,
          type: 'SYSTEM_ALERT',
          title: 'Invitation Rejected',
          body: `Freelancer declined your invitation for "${invitation.project.title}".`,
          link: `/client/browse`
        }
      })

      return inv
    })

    return res.status(200).json({ success: true, data: updated, message: 'Invitation rejected' })
  } catch (error) {
    console.error('Reject invitation error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error' })
  }
}
