import { Request, Response } from 'express';
import { prisma } from '../config/prisma';

const ADMIN_ONLY = (req: Request, res: Response): boolean => {
  if (req.user?.role !== 'ADMIN') {
    res.status(403).json({ success: false, message: 'Admins only.' });
    return false;
  }
  return true;
};

// ─────────────────────────────────────────────────────────────
// GET ALL DISPUTES (Admin)
// GET /api/disputes?status=&type=&search=&page=&limit=
// ─────────────────────────────────────────────────────────────
export const getAllDisputes = async (req: Request, res: Response) => {
  if (!ADMIN_ONLY(req, res)) return;

  try {
    const { status, type, search, page = '1', limit = '20' } = req.query;
    const skip = (parseInt(page as string) - 1) * parseInt(limit as string);

    const where: any = {};
    if (status) where.status = status;
    if (type) where.disputeType = type;
    if (search) {
      where.OR = [
        { reason: { contains: search as string, mode: 'insensitive' } },
        { details: { contains: search as string, mode: 'insensitive' } },
      ];
    }

    const [disputes, total] = await Promise.all([
      prisma.dispute.findMany({
        where,
        skip,
        take: parseInt(limit as string),
        orderBy: { openedAt: 'desc' },
        include: {
          project: { select: { id: true, title: true, budget: true } },
          client: {
            select: {
              id: true,
              name: true,
              email: true,
              profileImage: true,
              clientProfile: { select: { fullName: true } },
            },
          },
          freelancer: {
            select: {
              id: true,
              name: true,
              email: true,
              profileImage: true,
              freelancerProfile: { select: { fullName: true } },
            },
          },
          admin: { select: { fullName: true } },
          relatedDispute: { select: { id: true, status: true, filedBy: true } },
        },
      }),
      prisma.dispute.count({ where }),
    ]);

    // Stats counts across all disputes
    const [open, underReview, waitingForResponse, resolved, escalated, closed] =
      await Promise.all([
        prisma.dispute.count({ where: { status: 'OPEN' } }),
        prisma.dispute.count({ where: { status: 'UNDER_REVIEW' } }),
        prisma.dispute.count({ where: { status: 'WAITING_FOR_RESPONSE' } }),
        prisma.dispute.count({ where: { status: 'RESOLVED' } }),
        prisma.dispute.count({ where: { status: 'ESCALATED' } }),
        prisma.dispute.count({ where: { status: 'CLOSED' } }),
      ]);

    return res.json({
      success: true,
      disputes,
      pagination: { total, page: parseInt(page as string), limit: parseInt(limit as string) },
      stats: { open, underReview, waitingForResponse, resolved, escalated, closed },
    });
  } catch (err: any) {
    console.error('getAllDisputes error:', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// GET SINGLE DISPUTE (Admin)
// GET /api/disputes/:id
// ─────────────────────────────────────────────────────────────
export const getDisputeById = async (req: Request, res: Response) => {
  if (!ADMIN_ONLY(req, res)) return;

  try {
    const { id } = req.params;

    const dispute = await prisma.dispute.findUnique({
      where: { id },
      include: {
        project: {
          include: {
            category: true,
            subCategory: true,
            skills: { include: { skill: true } },
            contract: {
              include: {
                milestones: { orderBy: { order: "asc" } },
                freelancerProfile: { include: { user: { select: { name: true, profileImage: true } } } },
              },
            },
            proposals: {
              where: { status: "ACCEPTED" },
              take: 1,
            },
            chatRooms: {
              take: 1,
              include: {
                messages: {
                  take: 100,
                  orderBy: { sentAt: "desc" },
                  include: { sender: { select: { name: true, profileImage: true, role: true } } },
                },
              },
            },
          },
        },
        client: {
          select: {
            id: true,
            name: true,
            email: true,
            profileImage: true,
            clientProfile: { select: { fullName: true, company: true } },
          },
        },
        freelancer: {
          select: {
            id: true,
            name: true,
            email: true,
            profileImage: true,
            freelancerProfile: { select: { fullName: true, tagline: true } },
          },
        },
        admin: { select: { id: true, fullName: true } },
        relatedDispute: {
          include: {
            client: { select: { name: true } },
            freelancer: { select: { name: true } },
          }
        },
      },
    });

    if (!dispute) {
      return res.status(404).json({ success: false, message: 'Dispute not found' });
    }

    return res.json({ success: true, dispute });
  } catch (err: any) {
    console.error('getDisputeById error:', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// UPDATE DISPUTE STATUS (Admin)
// PATCH /api/disputes/:id/status
// body: { status: DisputeStatus }
// ─────────────────────────────────────────────────────────────
export const updateDisputeStatus = async (req: Request, res: Response) => {
  if (!ADMIN_ONLY(req, res)) return;

  const VALID_STATUSES = ['OPEN', 'UNDER_REVIEW', 'WAITING_FOR_RESPONSE', 'RESOLVED', 'ESCALATED', 'CLOSED'];

  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!VALID_STATUSES.includes(status)) {
      return res.status(400).json({ success: false, message: `Invalid status. Allowed: ${VALID_STATUSES.join(', ')}` });
    }

    const dispute = await prisma.dispute.findUnique({ where: { id } });
    if (!dispute) return res.status(404).json({ success: false, message: 'Dispute not found' });

    // Get admin profile id
    const adminProfile = await prisma.adminProfile.findUnique({
      where: { userId: req.user!.userId },
    });

    const updated = await prisma.dispute.update({
      where: { id },
      data: {
        status: status as any,
        ...(adminProfile ? { adminId: adminProfile.id } : {}),
      },
    });

    // Notify both parties
    const notifData = [
      { userId: dispute.clientId, title: 'Dispute Status Updated', body: `Your dispute status is now: ${status.replace(/_/g, ' ')}` },
      { userId: dispute.freelancerId, title: 'Dispute Status Updated', body: `Your dispute status is now: ${status.replace(/_/g, ' ')}` },
    ];
    await prisma.notification.createMany({
      data: notifData.map((n) => ({ ...n, type: 'DISPUTE_OPENED' as any, link: `/disputes/${id}` })),
    });

    return res.json({ success: true, dispute: updated });
  } catch (err: any) {
    console.error('updateDisputeStatus error:', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// RESOLVE DISPUTE (Admin)
// PATCH /api/disputes/:id/resolve
// body: { resolution, resolutionNote }
// ─────────────────────────────────────────────────────────────
export const resolveDispute = async (req: Request, res: Response) => {
  if (!ADMIN_ONLY(req, res)) return;

  const VALID_RESOLUTIONS = ['FAVOR_CLIENT', 'FAVOR_FREELANCER', 'PARTIAL_SPLIT', 'PROJECT_CANCELLED', 'DISMISSED'];

  try {
    const { id } = req.params;
    const { resolution, resolutionNote } = req.body;

    if (!VALID_RESOLUTIONS.includes(resolution)) {
      return res.status(400).json({ success: false, message: `Invalid resolution. Allowed: ${VALID_RESOLUTIONS.join(', ')}` });
    }

    const dispute = await prisma.dispute.findUnique({
      where: { id },
      include: { project: true },
    });
    if (!dispute) return res.status(404).json({ success: false, message: 'Dispute not found' });

    const adminProfile = await prisma.adminProfile.findUnique({
      where: { userId: req.user!.userId },
    });

    const updated = await prisma.dispute.update({
      where: { id },
      data: {
        status: 'RESOLVED' as any,
        resolution: resolution as any,
        resolutionNote,
        resolvedAt: new Date(),
        ...(adminProfile ? { adminId: adminProfile.id } : {}),
      },
    });

    // Update project and contract status based on resolution
    if (resolution === 'PROJECT_CANCELLED') {
      await prisma.project.update({ where: { id: dispute.projectId }, data: { status: 'CANCELLED' } });
      await prisma.contract.update({ where: { projectId: dispute.projectId }, data: { status: 'CANCELLED' } });
    } else {
      // For resolutions other than project cancellation, reset contract to active
      await prisma.contract.update({ where: { projectId: dispute.projectId }, data: { status: 'ACTIVE' } });
      await prisma.project.update({ where: { id: dispute.projectId }, data: { status: 'IN_PROGRESS' } });
    }

    // Log admin action
    if (adminProfile) {
      await prisma.adminLog.create({
        data: {
          adminProfileId: adminProfile.id,
          action: 'RESOLVED_DISPUTE',
          targetType: 'Dispute',
          targetId: id,
          note: `Resolution: ${resolution}. ${resolutionNote || ''}`,
        },
      });
    }

    // Notify both parties
    const resolutionText = resolution.replace(/_/g, ' ');
    const notifData = [
      {
        userId: dispute.clientId,
        title: 'Dispute Resolved',
        body: `Admin resolved your dispute: ${resolutionText}. ${resolutionNote || ''}`,
      },
      {
        userId: dispute.freelancerId,
        title: 'Dispute Resolved',
        body: `Admin resolved the dispute: ${resolutionText}. ${resolutionNote || ''}`,
      },
    ];
    await prisma.notification.createMany({
      data: notifData.map((n) => ({ ...n, type: 'DISPUTE_RESOLVED' as any, link: `/disputes/${id}` })),
    });

    return res.json({ success: true, dispute: updated, message: 'Dispute resolved successfully' });
  } catch (err: any) {
    console.error('resolveDispute error:', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// CREATE DISPUTE (Client or Freelancer)
// POST /api/disputes
// body: { projectId, disputeType, reason, details, evidenceUrls }
// ─────────────────────────────────────────────────────────────
export const createDispute = async (req: Request, res: Response) => {
  try {
    const { projectId, disputeType, reason, details, evidenceUrls } = req.body;
    const userId = req.user!.userId;
    const userRole = req.user!.role;

    if (!projectId || !disputeType || !reason) {
      return res.status(400).json({ success: false, message: 'projectId, disputeType, and reason are required' });
    }

    // Fetch project with contract
    const project = await prisma.project.findUnique({
      where: { id: projectId },
      include: {
        contract: { include: { freelancerProfile: { select: { userId: true } } } },
        clientProfile: { select: { userId: true } },
      },
    });

    if (!project) return res.status(404).json({ success: false, message: 'Project not found' });

    const clientUserId = project.clientProfile.userId;
    const freelancerUserId = project.contract?.freelancerProfile?.userId;

    if (!freelancerUserId) {
      return res.status(400).json({ success: false, message: 'No active contract found for this project' });
    }

    // Check the caller is one of the parties
    if (userId !== clientUserId && userId !== freelancerUserId) {
      return res.status(403).json({ success: false, message: 'You are not a party to this project' });
    }

    // Check if the user already filed a dispute for this project
    const existingSameFiler = await prisma.dispute.findFirst({
      where: {
        projectId,
        filedBy: userRole as any,
      },
    });

    if (existingSameFiler) {
      return res.status(409).json({ success: false, message: 'You have already filed a dispute for this project' });
    }

    // Check if the OTHER party already filed a dispute to link them
    const otherPartyRole = userRole === 'CLIENT' ? 'FREELANCER' : 'CLIENT';
    const relatedDispute = await prisma.dispute.findFirst({
      where: {
        projectId,
        filedBy: otherPartyRole as any,
      },
    });

    const dispute = await prisma.dispute.create({
      data: {
        projectId,
        clientId: clientUserId,
        freelancerId: freelancerUserId,
        disputeType: disputeType || 'PAYMENT',
        filedBy: userRole as any,
        reason,
        details,
        evidenceUrls: evidenceUrls || [],
        status: 'OPEN',
        relatedDisputeId: relatedDispute?.id,
      },
    });

    // If we just linked to a related dispute, update the other one too
    if (relatedDispute) {
      await prisma.dispute.update({
        where: { id: relatedDispute.id },
        data: { relatedDisputeId: dispute.id },
      });
    }

    // Update project and contract status to DISPUTED
    await prisma.project.update({ where: { id: projectId }, data: { status: 'DISPUTED' } });
    await prisma.contract.update({ where: { projectId }, data: { status: 'DISPUTED' } });

    // Notify admin(s)
    const admins = await prisma.user.findMany({ where: { role: 'ADMIN' } });
    if (admins.length > 0) {
      await prisma.notification.createMany({
        data: admins.map((a) => ({
          userId: a.id,
          type: 'DISPUTE_OPENED' as any,
          title: 'New Dispute Opened',
          body: `A dispute was opened for project: ${project.title}`,
          link: `/admin/disputes`,
        })),
      });
    }

    // Notify the other party
    const otherUserId = userId === clientUserId ? freelancerUserId : clientUserId;
    await prisma.notification.create({
      data: {
        userId: otherUserId,
        type: 'DISPUTE_OPENED' as any,
        title: 'Dispute Opened',
        body: `A dispute has been filed on project: ${project.title}`,
        link: `/disputes/${dispute.id}`,
      },
    });

    return res.status(201).json({ success: true, dispute, message: 'Dispute created successfully' });
  } catch (err: any) {
    console.error('createDispute error:', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// GET MY DISPUTE (Client or Freelancer by projectId)
// GET /api/disputes/my/:projectId
// ─────────────────────────────────────────────────────────────
export const getMyDispute = async (req: Request, res: Response) => {
  try {
    const { projectId } = req.params;
    const userId = req.user!.userId;
    const userRole = req.user!.role;

    // Find any dispute for this project where the requester is either the client or the freelancer
    const dispute = await prisma.dispute.findFirst({
      where: {
        projectId,
        OR: [{ clientId: userId }, { freelancerId: userId }],
      },
      include: {
        project: { select: { id: true, title: true, budget: true } },
        client: { select: { id: true, name: true, profileImage: true } },
        freelancer: { select: { id: true, name: true, profileImage: true } },
        admin: { select: { fullName: true } },
      },
    });

    if (!dispute) {
      return res.status(404).json({ success: false, message: 'No dispute found for this project' });
    }

    // Ensure user is a party
    if (dispute.clientId !== userId && dispute.freelancerId !== userId) {
      return res.status(403).json({ success: false, message: 'Not authorized' });
    }

    return res.json({ success: true, dispute });
  } catch (err: any) {
    console.error('getMyDispute error:', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// ADD DISPUTE NOTE (Admin)
// POST /api/disputes/:id/note
// Body: { note: string }
// ─────────────────────────────────────────────────────────────
export const addDisputeNote = async (req: Request, res: Response) => {
  if (!ADMIN_ONLY(req, res)) return;

  try {
    const { id } = req.params;
    const { note } = req.body;
    const userId = req.user!.userId;

    if (!note) {
      return res.status(400).json({ success: false, message: 'Note content is required' });
    }

    // Get admin profile
    const adminProfile = await prisma.adminProfile.findUnique({
      where: { userId },
    });

    if (!adminProfile) {
      return res.status(403).json({ success: false, message: 'Admin profile not found' });
    }

    // Verify dispute exists
    const dispute = await prisma.dispute.findUnique({ where: { id } });
    if (!dispute) {
      return res.status(404).json({ success: false, message: 'Dispute not found' });
    }

    // Create log entry as the "note"
    const log = await prisma.adminLog.create({
      data: {
        adminProfileId: adminProfile.id,
        action: 'ADD_DISPUTE_NOTE',
        targetType: 'Dispute',
        targetId: id,
        note,
      },
    });

    return res.json({ success: true, log, message: 'Note added to dispute history' });
  } catch (err: any) {
    console.error('addDisputeNote error:', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};
