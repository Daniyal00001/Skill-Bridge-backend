import { Request, Response } from 'express';
import { prisma } from '../config/prisma';

// ─────────────────────────────────────────────────────────────
// ADMIN DASHBOARD
// ─────────────────────────────────────────────────────────────
export const getAdminDashboard = async (req: Request, res: Response) => {
  try {
    const now = new Date();
    const firstDayOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);

    // Concurrently fetch counts
    const [
      totalUsers,
      newUsersThisMonth,
      openProjects,
      inProgressProjects,
      completedProjects,
      disputedProjects,
      openDisputes,
      pendingSkills,
      pendingProposals,
      bannedUsers,
    ] = await Promise.all([
      prisma.user.count(),
      prisma.user.count({ where: { createdAt: { gte: firstDayOfMonth } } }),
      prisma.project.count({ where: { status: 'OPEN' } }),
      prisma.project.count({ where: { status: 'IN_PROGRESS' } }),
      prisma.project.count({ where: { status: 'COMPLETED' } }),
      prisma.project.count({ where: { status: 'DISPUTED' } }),
      prisma.dispute.count({ where: { status: 'OPEN' } }),
      prisma.skill.count({ where: { status: 'PENDING' } }),
      prisma.proposal.count({ where: { status: 'PENDING' } }),
      prisma.user.count({ where: { isBanned: true } }),
    ]);

    // Calculate revenue (Sum of all RELEASED payments, assuming platform takes 10% fee)
    const payments = await prisma.payment.aggregate({
      _sum: { amount: true },
      where: { status: 'RELEASED' },
    });
    const totalRevenue = (payments._sum.amount || 0) * 0.10;

    // Fetch lists
    const [
      recentUsers,
      recentProjects,
      activeDisputes,
      pendingSkillsList,
      recentAdminLogs,
    ] = await Promise.all([
      prisma.user.findMany({
        take: 5,
        orderBy: { createdAt: 'desc' },
        select: { id: true, name: true, email: true, role: true, isEmailVerified: true, isBanned: true, profileImage: true },
      }),
      prisma.project.findMany({
        take: 5,
        orderBy: { createdAt: 'desc' },
        select: { id: true, title: true, size: true, status: true, budget: true },
      }),
      prisma.dispute.findMany({
        take: 5,
        where: { status: { not: 'CLOSED' } },
        orderBy: { openedAt: 'desc' },
        include: {
          client: { select: { name: true } },
          freelancer: { select: { name: true } },
          project: { select: { title: true } },
        },
      }),
      prisma.skill.findMany({
        take: 5,
        where: { status: 'PENDING' },
        orderBy: { createdAt: 'desc' },
        include: {
          freelancers: {
            take: 1,
            include: { freelancerProfile: { include: { user: { select: { name: true } } } } }
          }
        }
      }),
      prisma.adminLog.findMany({
        take: 5,
        orderBy: { createdAt: 'desc' },
      }).catch(() => []) // Catch if AdminLog model has issues or is empty
    ]);

    // Format disputes
    const formattedDisputes = activeDisputes.map(d => ({
      id: d.id,
      projectTitle: d.project.title,
      clientName: d.client.name,
      freelancerName: d.freelancer.name,
      reason: d.reason,
      status: d.status,
      openedAt: d.openedAt,
    }));

    // Format pending skills to include submitter name if available
    const formattedPendingSkills = pendingSkillsList.map(s => ({
      ...s,
      submittedBy: s.freelancers?.[0]?.freelancerProfile?.user?.name || 'Unknown'
    }));

    return res.status(200).json({
      success: true,
      data: {
        stats: {
          totalUsers,
          newUsersThisMonth,
          openProjects,
          inProgressProjects,
          completedProjects,
          disputedProjects,
          openDisputes,
          pendingSkills,
          pendingProposals,
          bannedUsers,
          totalRevenue,
        },
        lists: {
          recentUsers,
          recentProjects,
          activeDisputes: formattedDisputes,
          pendingSkills: formattedPendingSkills,
          recentAdminLogs,
        }
      }
    });
  } catch (error: any) {
    console.error("Admin Dashboard Error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// ─────────────────────────────────────────────────────────────
// CLIENT DASHBOARD
// ─────────────────────────────────────────────────────────────
export const getClientDashboard = async (req: Request, res: Response) => {
  try {
    const userId = req.user?.userId;
    const clientProfile = await prisma.clientProfile.findUnique({
      where: { userId }
    });

    if (!clientProfile) {
      return res.status(404).json({ success: false, message: "Client profile not found" });
    }

    const clientId = clientProfile.id;

    // Concurrently fetch counts & data
    const [
      activeProjects,
      completedProjects,
      disputedProjects,
      openProjectsList,
      inProgressProjectsList,
      pendingInvitations,
      recentProposals,
    ] = await Promise.all([
      prisma.project.count({ where: { clientProfileId: clientId, status: { in: ['OPEN', 'IN_PROGRESS', 'UNDER_REVIEW', 'REVISION_REQUESTED'] } } }),
      prisma.project.count({ where: { clientProfileId: clientId, status: 'COMPLETED' } }),
      prisma.project.count({ where: { clientProfileId: clientId, status: 'DISPUTED' } }),
      prisma.project.findMany({
        where: { clientProfileId: clientId, status: 'OPEN' },
        take: 2,
        orderBy: { createdAt: 'desc' },
      }),
      prisma.project.findMany({
        where: { clientProfileId: clientId, status: 'IN_PROGRESS' },
        select: { budget: true }
      }),
      prisma.invitation.findMany({
        where: { clientProfileId: clientId, status: 'PENDING' },
        take: 5,
        orderBy: { createdAt: 'desc' },
        include: { freelancerProfile: { include: { user: { select: { name: true, profileImage: true } } } } }
      }),
      prisma.proposal.findMany({
        where: { project: { clientProfileId: clientId } },
        take: 5,
        orderBy: { submittedAt: 'desc' },
        include: {
          project: { select: { title: true } },
          freelancerProfile: { include: { user: { select: { name: true, profileImage: true } } } }
        }
      })
    ]);

    const committedBudget = inProgressProjectsList.reduce((acc, p) => acc + (p.budget || 0), 0);
    const pendingProposalsCount = await prisma.proposal.count({ where: { project: { clientProfileId: clientId }, status: 'PENDING' } });
    const shortlistedProposalsCount = await prisma.proposal.count({ where: { project: { clientProfileId: clientId }, status: 'SHORTLISTED' } });

    // formatted lists
    const formattedProposals = recentProposals.map(p => ({
      id: p.id,
      projectId: p.projectId,
      projectTitle: p.project?.title,
      freelancerName: p.freelancerProfile?.user?.name,
      avatar: p.freelancerProfile?.user?.profileImage,
      proposedPrice: p.proposedPrice,
      status: p.status,
    }));

    const formattedInvitations = pendingInvitations.map(i => ({
      id: i.id,
      freelancerName: i.freelancerProfile?.user?.name,
      avatar: i.freelancerProfile?.user?.profileImage,
      status: i.status,
    }));

    return res.status(200).json({
      success: true,
      data: {
        stats: {
          activeProjects,
          completedProjects,
          disputedProjects,
          committedBudget,
          pendingProposals: pendingProposalsCount,
          shortlistedProposals: shortlistedProposalsCount,
        },
        lists: {
          openProjects: openProjectsList,
          recentProposals: formattedProposals,
          pendingInvitations: formattedInvitations,
        }
      }
    });

  } catch (error: any) {
    console.error("Client Dashboard Error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// ─────────────────────────────────────────────────────────────
// FREELANCER DASHBOARD
// ─────────────────────────────────────────────────────────────
export const getFreelancerDashboard = async (req: Request, res: Response) => {
  try {
    const userId = req.user?.userId;
    const freelancerProfile = await prisma.freelancerProfile.findUnique({
      where: { userId }
    });

    if (!freelancerProfile) {
      return res.status(404).json({ success: false, message: "Freelancer profile not found" });
    }

    const fid = freelancerProfile.id;

    const now = new Date();
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);

    const [
      activeProposalsCount,
      shortlistedProposalsCount,
      proposalsThisMonth,
      activeContractsCount,
      completedJobs,
      pendingInvitationsCount,
      activeMilestones,
      recentTokenTxs,
      activeProposalsList,
    ] = await Promise.all([
      prisma.proposal.count({ where: { freelancerProfileId: fid, status: 'PENDING' } }),
      prisma.proposal.count({ where: { freelancerProfileId: fid, status: 'SHORTLISTED' } }),
      prisma.proposal.count({ where: { freelancerProfileId: fid, submittedAt: { gte: startOfMonth } } }),
      prisma.contract.count({ where: { freelancerProfileId: fid, status: 'ACTIVE' } }),
      prisma.contract.count({ where: { freelancerProfileId: fid, status: 'COMPLETED' } }),
      prisma.invitation.count({ where: { freelancerProfileId: fid, status: 'PENDING' } }),
      prisma.milestone.findMany({
        where: { contract: { freelancerProfileId: fid }, status: { in: ['IN_PROGRESS', 'SUBMITTED', 'REVISION_REQUESTED', 'APPROVED'] } },
        take: 5,
        orderBy: { dueDate: 'asc' },
        include: { contract: { select: { project: { select: { title: true } } } } }
      }),
      prisma.tokenTransaction.findMany({
        where: { freelancerProfileId: fid },
        take: 5,
        orderBy: { createdAt: 'desc' },
      }),
      prisma.proposal.findMany({
        where: { freelancerProfileId: fid, status: { in: ['PENDING', 'SHORTLISTED'] } },
        take: 5,
        orderBy: { submittedAt: 'desc' },
        include: { project: { select: { title: true } } }
      })
    ]);

    // Earnings computations
    const [totalEarningsRes, monthlyEarningsRes] = await Promise.all([
      prisma.payment.aggregate({
        _sum: { amount: true },
        where: { status: 'RELEASED', contract: { freelancerProfileId: fid } }
      }),
      prisma.payment.aggregate({
        _sum: { amount: true },
        where: { status: 'RELEASED', contract: { freelancerProfileId: fid }, releasedAt: { gte: startOfMonth } }
      })
    ]);

    const totalEarnings = totalEarningsRes._sum.amount || 0;
    const monthlyEarnings = monthlyEarningsRes._sum.amount || 0;

    // Average Rating from Reviews
    const reviews = await prisma.review.aggregate({
      _avg: { rating: true },
      _count: { rating: true },
      where: { receiverId: userId }
    });

    const formattedMilestones = activeMilestones.map(m => ({
      id: m.id,
      title: m.title,
      projectTitle: m.contract?.project?.title,
      status: m.status,
      dueDate: m.dueDate,
      amount: m.amount,
      allowedRevisions: m.allowedRevisions,
      revisionsUsed: m.revisionsUsed,
    }));

    const formattedProposals = activeProposalsList.map(p => ({
      id: p.id,
      projectTitle: p.project?.title,
      proposedPrice: p.proposedPrice,
      status: p.status,
      tokenCost: p.tokenCost,
    }));

    return res.status(200).json({
      success: true,
      data: {
        stats: {
          activeProposals: activeProposalsCount,
          shortlistedProposals: shortlistedProposalsCount,
          proposalsThisMonth,
          activeContractsCount,
          completedJobs,
          pendingInvitationsCount,
          totalEarnings,
          monthlyEarnings,
          skillTokenBalance: freelancerProfile.skillTokenBalance,
          profileCompletion: freelancerProfile.profileCompletion,
          averageRating: reviews._avg.rating || 5.0,
          totalReviews: reviews._count.rating || 0
        },
        lists: {
          activeMilestones: formattedMilestones,
          recentTokenTxs,
          activeProposals: formattedProposals,
        }
      }
    });

  } catch (error: any) {
    console.error("Freelancer Dashboard Error:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};
