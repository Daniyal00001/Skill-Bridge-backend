import Stripe from 'stripe';
import { prisma } from '../config/prisma';
import { createNotification } from '../services/notification.service';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2026-03-25.dahlia',
});

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
    const [open, underReview, resolved, closed] =
      await Promise.all([
        prisma.dispute.count({ where: { status: 'OPEN' } }),
        prisma.dispute.count({ where: { status: 'UNDER_REVIEW' } }),
        prisma.dispute.count({ where: { status: 'RESOLVED' } }),
        prisma.dispute.count({ where: { status: 'CLOSED' } }),
      ]);

    return res.json({
      success: true,
      disputes,
      pagination: { total, page: parseInt(page as string), limit: parseInt(limit as string) },
      stats: { open, underReview, resolved, closed },
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
    const { id: disputeId } = req.params;

    // 1. Fetch the dispute to get the opening timestamp
    const baseDispute = await prisma.dispute.findUnique({
      where: { id: disputeId },
      select: { openedAt: true }
    });

    if (!baseDispute) {
      return res.status(404).json({ success: false, message: 'Dispute not found' });
    }

    // 2. Fetch full detail with messages sent BEFORE or AT the time of dispute
    const dispute = await prisma.dispute.findUnique({
      where: { id: disputeId },
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
                chatRooms: {
                  include: {
                    messages: {
                      where: {
                        sentAt: { lte: baseDispute.openedAt }
                      },
                      take: 100,
                      orderBy: { sentAt: "desc" },
                      include: { sender: { select: { name: true, profileImage: true, role: true } } },
                    },
                  },
                },
              },
            },
            proposals: {
              where: { status: "ACCEPTED" },
              take: 1,
            },
            chatRooms: {
              include: {
                messages: {
                  where: {
                    sentAt: { lte: baseDispute.openedAt }
                  },
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

    // 3. Find ALL rooms involving these two people to capture logs with null projectId
    const [clientProfile, freelancerProfile] = await Promise.all([
      prisma.clientProfile.findUnique({ where: { userId: dispute.clientId } }),
      prisma.freelancerProfile.findUnique({ where: { userId: dispute.freelancerId } }),
    ]);

    if (clientProfile && freelancerProfile) {
      const globalRooms = await prisma.chatRoom.findMany({
        where: {
          AND: [
            { clientProfileId: clientProfile.id },
            { freelancerProfileId: freelancerProfile.id },
          ]
        },
        include: {
          messages: {
            where: {
              sentAt: { lte: baseDispute.openedAt }
            },
            take: 100,
            orderBy: { sentAt: "desc" },
            include: { sender: { select: { name: true, profileImage: true, role: true } } },
          },
        },
      });

      // Attach these rooms to the project object so the frontend can find them
      const project = (dispute.project || {}) as any;
      const existingRooms = project.chatRooms || [];
      const allRoomIds = new Set(existingRooms.map((r: any) => r.id));
      
      const uniqueGlobalRooms = globalRooms.filter(r => !allRoomIds.has(r.id));
      project.chatRooms = [...existingRooms, ...uniqueGlobalRooms];
    }

    return res.json({ success: true, dispute });
  } catch (err: any) {
    console.error('getDisputeById error:', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// UPDATE DISPUTE SUMMARY (Admin)
// PATCH /api/disputes/:id/summary
// ─────────────────────────────────────────────────────────────
export const updateDisputeSummary = async (req: Request, res: Response) => {
  if (!ADMIN_ONLY(req, res)) return;

  try {
    const { id } = req.params;
    const { summary } = req.body;

    if (summary === undefined) {
      return res.status(400).json({ success: false, message: 'Summary is required' });
    }

    const dispute = await prisma.dispute.update({
      where: { id },
      data: { summary },
      include: {
        admin: { select: { fullName: true } }
      }
    });

    return res.json({ success: true, dispute });
  } catch (err: any) {
    console.error('updateDisputeSummary error:', err);
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

  const VALID_STATUSES = ['OPEN', 'UNDER_REVIEW', 'RESOLVED', 'CLOSED'];

  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!VALID_STATUSES.includes(status)) {
      return res.status(400).json({ success: false, message: `Invalid status. Allowed: ${VALID_STATUSES.join(', ')}` });
    }

    const dispute = await prisma.dispute.findUnique({ where: { id: id as string } });
    if (!dispute) return res.status(404).json({ success: false, message: 'Dispute not found' });

    // Get admin profile id
    const adminProfile = await prisma.adminProfile.findUnique({
      where: { userId: req.user!.userId },
    });

    const updated = await prisma.dispute.update({
      where: { id: id as string },
      data: {
        status: status as any,
        ...(adminProfile ? { adminId: adminProfile.id } : {}),
      },
    });

    // Notify both parties
    await Promise.all([
      createNotification({
        userId: dispute.clientId,
        type: 'DISPUTE_OPENED',
        title: 'Dispute Status Updated',
        body: `Your dispute status is now: ${status.replace(/_/g, ' ')}`,
        link: `/disputes/${id}`,
      }),
      createNotification({
        userId: dispute.freelancerId,
        type: 'DISPUTE_OPENED',
        title: 'Dispute Status Updated',
        body: `Your dispute status is now: ${status.replace(/_/g, ' ')}`,
        link: `/disputes/${id}`,
      }),
    ]);

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

  const VALID_RESOLUTIONS = [
    "FAVOR_CLIENT",
    "FAVOR_FREELANCER",
    "PARTIAL_SPLIT",
    "PROJECT_CANCELLED",
    "DISMISSED",
  ];

  try {
    const { id } = req.params;
    const { resolution, resolutionNote } = req.body;

    if (!VALID_RESOLUTIONS.includes(resolution)) {
      return res.status(400).json({
        success: false,
        message: `Invalid resolution. Allowed: ${VALID_RESOLUTIONS.join(", ")}`,
      });
    }

    const dispute = await prisma.dispute.findUnique({
      where: { id: id as string },
      include: { project: true },
    });
    if (!dispute)
      return res
        .status(404)
        .json({ success: false, message: "Dispute not found" });

    const adminProfile = await prisma.adminProfile.findUnique({
      where: { userId: req.user!.userId },
    });

    const updated = await prisma.$transaction(async (tx) => {
      const disputeUpdate = await tx.dispute.update({
        where: { id: id as string },
        data: {
          status: "RESOLVED" as any,
          resolution: resolution as any,
          resolutionNote,
          resolvedAt: new Date(),
          ...(adminProfile ? { adminId: adminProfile.id } : {}),
        },
      });

      // Find the contract and escrowed payments
      const contract = await tx.contract.findUnique({
        where: { projectId: dispute.projectId },
        include: {
          payments: { where: { status: "HELD_IN_ESCROW" } },
          freelancerProfile: true,
          project: { include: { clientProfile: true } },
        },
      });

      if (contract && contract.payments.length > 0) {
        const totalEscrow = contract.payments.reduce(
          (sum, p) => sum + p.amount,
          0
        );

        if (resolution === "FAVOR_FREELANCER") {
          // Calculate 10% platform fee
          const platformFee = totalEscrow * 0.10;
          const freelancerNet = totalEscrow - platformFee;

          // Release all to freelancer (INTERNAL BALANCE)
          await tx.payment.updateMany({
            where: { contractId: contract.id, status: "HELD_IN_ESCROW" },
            data: { status: "RELEASED", releasedAt: new Date() },
          });

          await tx.freelancerProfile.update({
            where: { id: contract.freelancerProfileId },
            data: { balance: { increment: freelancerNet } },
          });

          // Record Platform Earning
          await tx.platformEarning.create({
            data: {
              amount: platformFee,
              type: 'PROJECT_FEE',
              description: `10% fee from dispute resolution (FAVOR_FREELANCER) on project "${dispute.project?.title || ''}"`,
              metadata: {
                disputeId: dispute.id,
                projectId: dispute.projectId,
                freelancerId: contract.freelancerProfileId,
                grossAmount: totalEscrow,
                feeAmount: platformFee,
                netAmount: freelancerNet,
                resolution
              }
            }
          });

          // Mark associated milestones as APPROVED
          const milestoneIds = contract.payments
            .map((p) => p.milestoneId)
            .filter(Boolean) as string[];
          if (milestoneIds.length > 0) {
            await tx.milestone.updateMany({
              where: { id: { in: milestoneIds } },
              data: { status: "APPROVED", approvedAt: new Date() },
            });
          }
        } else if (
          resolution === "FAVOR_CLIENT" ||
          resolution === "PROJECT_CANCELLED"
        ) {
          // ... (existing stripe refund logic) ...
          for (const payment of contract.payments) {
            if (payment.transactionId) {
              try {
                await stripe.refunds.create({
                  payment_intent: payment.transactionId,
                });
              } catch (stripeErr: any) {
                console.error(`Stripe refund failed for PI ${payment.transactionId}:`, stripeErr.message);
              }
            }
          }

          // Refund all to client (MARK DB)
          await tx.payment.updateMany({
            where: { contractId: contract.id, status: "HELD_IN_ESCROW" },
            data: { status: "REFUNDED" },
          });

          // Mark associated milestones as REJECTED
          const milestoneIds = contract.payments
            .map((p) => p.milestoneId)
            .filter(Boolean) as string[];
          if (milestoneIds.length > 0) {
            await tx.milestone.updateMany({
              where: { id: { in: milestoneIds } },
              data: { status: "REJECTED" },
            });
          }
        } else if (resolution === "PARTIAL_SPLIT") {
          // Default 50/50 split
          const totalFreelancerGross = totalEscrow / 2;
          const platformFee = totalFreelancerGross * 0.10;
          const freelancerNet = totalFreelancerGross - platformFee;

          for (const payment of contract.payments) {
            const halfAmount = payment.amount / 2;
            if (payment.transactionId) {
              try {
                await stripe.refunds.create({
                  payment_intent: payment.transactionId,
                  amount: Math.round(halfAmount * 100), // 50% refund
                });
              } catch (stripeErr: any) {
                console.error(`Partial Stripe refund failed:`, stripeErr.message);
              }
            }

            // Update original payment to the RELEASED portion (freelancer gets this)
            await tx.payment.update({
              where: { id: payment.id },
              data: {
                amount: halfAmount,
                status: "RELEASED",
                releasedAt: new Date(),
              },
            });

            // Create a new record for the REFUNDED portion (client got this back)
            await tx.payment.create({
              data: {
                contractId: contract.id,
                amount: halfAmount,
                status: "REFUNDED",
                transactionId: payment.transactionId,
                paidAt: payment.paidAt,
              },
            });
          }

          await tx.freelancerProfile.update({
            where: { id: contract.freelancerProfileId },
            data: { balance: { increment: freelancerNet } },
          });

          // Record Platform Earning for the released portion
          await tx.platformEarning.create({
            data: {
              amount: platformFee,
              type: 'PROJECT_FEE',
              description: `10% fee from partial dispute resolution on project "${dispute.project?.title || ''}"`,
              metadata: {
                disputeId: dispute.id,
                projectId: dispute.projectId,
                freelancerId: contract.freelancerProfileId,
                grossAmount: totalFreelancerGross,
                feeAmount: platformFee,
                netAmount: freelancerNet,
                resolution
              }
            }
          });

          // Mark milestones as APPROVED
          const milestoneIds = contract.payments
            .map((p) => p.milestoneId)
            .filter(Boolean) as string[];
          if (milestoneIds.length > 0) {
            await tx.milestone.updateMany({
              where: { id: { in: milestoneIds } },
              data: { status: "APPROVED", approvedAt: new Date() },
            });
          }
        }
      }

      // Update project/contract status
      const allMilestones = await tx.milestone.findMany({
        where: { contractId: contract?.id || "" },
      });
      const allDone = allMilestones.every((m) =>
        ["APPROVED", "REJECTED"].includes(m.status)
      );

      if (resolution === "PROJECT_CANCELLED") {
        await tx.project.update({
          where: { id: dispute.projectId },
          data: { status: "CANCELLED" },
        });
        await tx.contract.update({
          where: { projectId: dispute.projectId },
          data: { status: "CANCELLED" },
        });
      } else if (allDone) {
        await tx.contract.update({
          where: { projectId: dispute.projectId },
          data: { status: "COMPLETED", endDate: new Date() },
        });
        await tx.project.update({
          where: { id: dispute.projectId },
          data: { status: "COMPLETED" },
        });
      } else {
        await tx.contract.update({
          where: { projectId: dispute.projectId },
          data: { status: "ACTIVE" },
        });
        await tx.project.update({
          where: { id: dispute.projectId },
          data: { status: "IN_PROGRESS" },
        });
      }

      // ── Notify both parties (FIXED: INSIDE TRANSACTION) ──
      const resolutionText = resolution.replace(/_/g, " ");
      await Promise.all([
        createNotification({
          userId: dispute.clientId,
          type: "DISPUTE_RESOLVED",
          title: "Dispute Resolved",
          body: `Admin resolved your dispute: ${resolutionText}. ${resolutionNote || ""}`,
          link: `/disputes/${id}`,
        }, tx),
        createNotification({
          userId: dispute.freelancerId,
          type: "DISPUTE_RESOLVED",
          title: "Dispute Resolved",
          body: `Admin resolved the dispute: ${resolutionText}. ${resolutionNote || ""}`,
          link: `/disputes/${id}`,
        }, tx),
      ]);

      return disputeUpdate;
    });

    // Log admin action
    if (adminProfile) {
      await prisma.adminLog.create({
        data: {
          adminProfileId: adminProfile.id,
          action: "RESOLVED_DISPUTE",
          targetType: "Dispute",
          targetId: id as string,
          note: `Resolution: ${resolution}. ${resolutionNote || ""}`,
        },
      });
    }

    return res.json({
      success: true,
      dispute: updated,
      message: "Dispute resolved successfully",
    });
  } catch (err: any) {
    console.error("resolveDispute error:", err);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
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

    // Check if the user already has an ACTIVE dispute for this project
    const activeDispute = await prisma.dispute.findFirst({
      where: {
        projectId,
        filedBy: userRole as any,
        status: { notIn: ["RESOLVED", "CLOSED"] as any },
      },
    });

    if (activeDispute) {
      return res.status(409).json({
        success: false,
        message: "You already have an active dispute for this project.",
      });
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
      await Promise.all(
        admins.map((a) =>
          createNotification({
            userId: a.id,
            type: 'DISPUTE_OPENED',
            title: 'New Dispute Opened',
            body: `A dispute was opened for project: ${project.title}`,
            link: `/admin/disputes`,
          })
        )
      );
    }

    // Notify the other party
    const otherUserId = userId === clientUserId ? freelancerUserId : clientUserId;
    await createNotification({
      userId: otherUserId,
      type: 'DISPUTE_OPENED',
      title: 'Dispute Opened',
      body: `A dispute has been filed on project: ${project.title}`,
      link: `/disputes/${dispute.id}`,
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

    // Find the latest dispute for this project involving the requester
    const dispute = await prisma.dispute.findFirst({
      where: {
        projectId: projectId as string,
        OR: [{ clientId: userId as string }, { freelancerId: userId as string }],
      },
      orderBy: { openedAt: "desc" },
      include: {
        project: { select: { id: true, title: true, budget: true } },
        client: { select: { id: true, name: true, profileImage: true } },
        freelancer: { select: { id: true, name: true, profileImage: true } },
        admin: { select: { id: true, fullName: true } },
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
    const dispute = await prisma.dispute.findUnique({ where: { id: id as string } });
    if (!dispute) {
      return res.status(404).json({ success: false, message: 'Dispute not found' });
    }

    // Create log entry as the "note"
    const log = await prisma.adminLog.create({
      data: {
        adminProfileId: adminProfile.id,
        action: 'ADD_DISPUTE_NOTE',
        targetType: 'Dispute',
        targetId: id as string,
        note,
      },
    });

    return res.json({ success: true, log, message: 'Note added to dispute history' });
  } catch (err: any) {
    console.error('addDisputeNote error:', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};
