import { Request, Response } from 'express';
import { prisma } from '../config/prisma';

// ─────────────────────────────────────────────────────────────
// GET ALL SKILLS (Admin, filter by status)
// GET /api/admin/skills?status=PENDING
// ─────────────────────────────────────────────────────────────
export const getAdminSkills = async (req: Request, res: Response) => {
  try {
    const { status } = req.query;
    
    // Only allow Admins to access this.
    if (req.user?.role !== 'ADMIN') {
       return res.status(403).json({ success: false, message: "Forbidden: Admins only" });
    }

    if (status === 'REJECTED') {
      const rejectedSkills = await prisma.rejectedSkill.findMany({
        orderBy: { createdAt: 'desc' }
      });
      // Map to same structure as Skill for frontend consistency
      const skills = rejectedSkills.map(s => ({
        id: s.id,
        name: s.name,
        status: 'REJECTED',
        createdAt: s.createdAt
      }));
      return res.status(200).json({ success: true, skills });
    }

    const whereClause: any = {};
    if (status && status !== 'ALL') {
      whereClause.status = status;
    }

    const skills = await prisma.skill.findMany({
      where: whereClause,
      orderBy: { createdAt: 'desc' }
    });

    return res.status(200).json({ success: true, skills });
  } catch (error: any) {
    console.error("Admin Get Skills Error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// ─────────────────────────────────────────────────────────────
// UPDATE SKILL STATUS
// PATCH /api/admin/skills/:id/status
// ─────────────────────────────────────────────────────────────
export const updateSkillStatus = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: "Forbidden: Admins only" });
    }

    if (!['APPROVED', 'REJECTED', 'PENDING'].includes(status)) {
      return res.status(400).json({ success: false, message: "Invalid status value" });
    }

    if (status === 'REJECTED') {
      const skillToDelete = await prisma.skill.findUnique({ where: { id } });
      if (!skillToDelete) {
        return res.status(404).json({ success: false, message: "Skill not found" });
      }

      const skill = await prisma.$transaction(async (tx) => {
        // Create in RejectedSkill
        await tx.rejectedSkill.upsert({
          where: { name: skillToDelete.name },
          update: {},
          create: { name: skillToDelete.name }
        });

        // Explicitly delete from join tables (MongoDB workaround for Cascade)
        // Use the ID from the record we just found to ensure consistency
        const fsDeleted = await tx.freelancerSkill.deleteMany({ where: { skillId: skillToDelete.id } });
        const psDeleted = await tx.projectSkill.deleteMany({ where: { skillId: skillToDelete.id } });

        console.log(`[Rejection] Deleted ${fsDeleted.count} freelancer skills and ${psDeleted.count} project skills for ${skillToDelete.name}`);

        // Delete from Skill
        return await tx.skill.delete({ where: { id: skillToDelete.id } });
      });

      return res.status(200).json({ success: true, message: `Skill rejected and moved to blocked list`, skill });
    }

    const skill = await prisma.skill.update({
      where: { id },
      data: { status }
    });

    return res.status(200).json({ success: true, message: `Skill ${status.toLowerCase()} successfully`, skill });
  } catch (error: any) {
    console.error("Admin Update Skill Error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// ─────────────────────────────────────────────────────────────
// GET USER PROFILE (Admin)
// GET /api/admin/users/:id/profile
// ─────────────────────────────────────────────────────────────
export const getAdminUserProfile = async (req: Request, res: Response) => {
  try {
    const { id: userId } = req.params;

    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: "Forbidden: Admins only" });
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        clientProfile: {
          include: {
            projects: {
              take: 5,
              orderBy: { createdAt: "desc" },
              include: {
                contract: {
                  include: {
                    milestones: { orderBy: { order: "asc" } }
                  }
                }
              }
            },
            _count: {
              select: { projects: true }
            }
          }
        },
        freelancerProfile: {
          include: {
            skills: { include: { skill: true } },
            portfolioItems: true,
            educations: true,
            certificates: true,
            contracts: {
              take: 5,
              orderBy: { createdAt: "desc" },
              include: {
                project: {
                  select: { id: true, title: true, status: true }
                },
                milestones: {
                  orderBy: { order: "asc" }
                }
              }
            },
            _count: {
              select: { 
                gigs: true,
                contracts: true
              }
            }
          }
        },
        reviewsReceived: {
          take: 5,
          orderBy: { submittedAt: 'desc' },
          include: { giver: { select: { name: true, profileImage: true } } }
        },
        disputesAsClient: {
          take: 5,
          orderBy: { openedAt: 'desc' },
          select: { id: true, status: true, reason: true, openedAt: true }
        },
        disputesAsFreelancer: {
          take: 5,
          orderBy: { openedAt: 'desc' },
          select: { id: true, status: true, reason: true, openedAt: true }
        },
        _count: {
          select: {
            reviewsReceived: true,
            disputesAsClient: true,
            disputesAsFreelancer: true
          }
        }
      }
    });

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Return a unified profile object
    return res.status(200).json({ 
      success: true, 
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        profileImage: user.profileImage,
        createdAt: user.createdAt,
        isEmailVerified: user.isEmailVerified,
        isIdVerified: user.isIdVerified,
        isPhoneVerified: user.isPhoneVerified,
        isPaymentVerified: user.isPaymentVerified,
        isBanned: user.isBanned,
        banReason: user.banReason,
        lastActiveAt: user.lastActiveAt,
        clientProfile: user.clientProfile,
        freelancerProfile: user.freelancerProfile,
        reviews: user.reviewsReceived,
        _count: user._count,
        disputeHistory: [...user.disputesAsClient, ...user.disputesAsFreelancer].sort((a, b) => 
          new Date(b.openedAt).getTime() - new Date(a.openedAt).getTime()
        )
      }
    });
  } catch (error: any) {
    console.error("Admin Get User Profile Error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// ─────────────────────────────────────────────────────────────
// GET PENDING IDENTITY VERIFICATIONS
// GET /api/admin/verifications/pending
// ─────────────────────────────────────────────────────────────
export const getPendingVerifications = async (req: Request, res: Response) => {
  try {
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: "Forbidden: Admins only" });
    }

    const users = await prisma.user.findMany({
      where: {
        idVerificationStatus: "PENDING"
      },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        idDocumentUrl: true,
        createdAt: true,
        idVerificationStatus: true,
        idRejectionReason: true,
      },
      orderBy: { createdAt: 'asc' }
    });

    return res.status(200).json({ success: true, users });
  } catch (error: any) {
    console.error("Admin Get Pending Verifications Error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// ─────────────────────────────────────────────────────────────
// GET ALL IDENTITY VERIFICATIONS (with optional status filter)
// GET /api/admin/verifications?status=PENDING|APPROVED|REJECTED|ALL
// ─────────────────────────────────────────────────────────────
export const getAllVerifications = async (req: Request, res: Response) => {
  try {
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: "Forbidden: Admins only" });
    }

    const { status } = req.query;

    // Build where clause — only include users who have submitted a verification
    const where: any = {
      idVerificationStatus: { not: "UNSUBMITTED" }
    };

    if (status && status !== 'ALL') {
      where.idVerificationStatus = status;
    }

    const users = await prisma.user.findMany({
      where,
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        idDocumentUrl: true,
        createdAt: true,
        updatedAt: true,
        idVerificationStatus: true,
        idRejectionReason: true,
      },
      orderBy: { updatedAt: 'desc' }
    });

    // Return counts per status for tab badges
    const counts = await prisma.user.groupBy({
      by: ['idVerificationStatus'],
      where: { idVerificationStatus: { not: "UNSUBMITTED" } },
      _count: { idVerificationStatus: true }
    });

    const statusCounts = {
      ALL: 0,
      PENDING: 0,
      APPROVED: 0,
      REJECTED: 0,
    };
    counts.forEach(c => {
      const s = c.idVerificationStatus as keyof typeof statusCounts;
      statusCounts[s] = c._count.idVerificationStatus;
      statusCounts.ALL += c._count.idVerificationStatus;
    });

    return res.status(200).json({ success: true, users, statusCounts });
  } catch (error: any) {
    console.error("Admin Get All Verifications Error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// ─────────────────────────────────────────────────────────────
// APPROVE IDENTITY VERIFICATION
// POST /api/admin/verifications/approve/:userId
// ─────────────────────────────────────────────────────────────
export const approveVerification = async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: "Forbidden: Admins only" });
    }

    const user = await prisma.user.update({
      where: { id: userId },
      data: {
        isIdVerified: true,
        idVerificationStatus: "APPROVED",
        idRejectionReason: null
      }
    });

    return res.status(200).json({ success: true, message: "User identity verified successfully", user });
  } catch (error: any) {
    console.error("Admin Approve Verification Error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// ─────────────────────────────────────────────────────────────
// REJECT IDENTITY VERIFICATION
// POST /api/admin/verifications/reject/:userId
// ─────────────────────────────────────────────────────────────
export const rejectVerification = async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;
    const { reason } = req.body;
    
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: "Forbidden: Admins only" });
    }

    const userToReject = await prisma.user.findUnique({ where: { id: userId }});
    if (!userToReject) return res.status(404).json({ success: false, message: "User not found" });

    // Assuming we do NOT delete the image from Cloudinary so we have a record, OR we can delete it. Let's not delete it for safety, or actually let's just clear the URL. The implementation plan says "clear URL".
    // I won't delete it from Cloudinary here to avoid complex imports if not needed, just DB clear.
    const user = await prisma.user.update({
      where: { id: userId },
      data: {
        isIdVerified: false,
        idVerificationStatus: "REJECTED",
        idRejectionReason: reason || "Document invalid or unclear",
        idDocumentUrl: null
      }
    });

    return res.status(200).json({ success: true, message: "User identity rejected", user });
  } catch (error: any) {
    console.error("Admin Reject Verification Error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};
