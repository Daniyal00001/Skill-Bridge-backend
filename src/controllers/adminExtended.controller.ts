import { Request, Response } from 'express';
import { prisma } from '../config/prisma';
import { getCache, setCache, deletePatternCache } from '../utils/redis';

// ─────────────────────────────────────────────────────────────
// GET ALL USERS (Admin)
// GET /api/admin/users?role=CLIENT|FREELANCER&search=&page=1
// ─────────────────────────────────────────────────────────────
export const getAllUsers = async (req: Request, res: Response) => {
  try {
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const { role, search, page = '1', limit = '20', banned, startDate, endDate } = req.query;
    const skip = (parseInt(page as string) - 1) * parseInt(limit as string);

    // Protocol Cache Logic
    const cacheKey = `admin:users:${role || 'all'}:${search || ''}:${banned || 'f'}:${startDate || ''}:${endDate || ''}:${page}:${limit}`;
    const cached = await getCache<any>(cacheKey);
    if (cached) return res.status(200).json({ success: true, ...cached });

    const where: any = {};
    
    // Role filtering (Exclude admins by default)
    if (role && role !== 'ALL') {
      where.role = role;
    } else {
      where.role = { not: 'ADMIN' };
    }

    // Date range filtering
    if (startDate || endDate) {
      where.createdAt = {};
      if (startDate) {
        const start = new Date(startDate as string);
        start.setHours(0, 0, 0, 0);
        where.createdAt.gte = start;
      }
      if (endDate) {
        const end = new Date(endDate as string);
        end.setHours(23, 59, 59, 999);
        where.createdAt.lte = end;
      }
    }

    if (banned === 'true') where.isBanned = true;
    if (search) {
      where.OR = [
        { name: { contains: search as string, mode: 'insensitive' } },
        { email: { contains: search as string, mode: 'insensitive' } },
      ];
    }

    const [users, total] = await Promise.all([
      prisma.user.findMany({
        where,
        skip,
        take: parseInt(limit as string),
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
          profileImage: true,
          isEmailVerified: true,
          isIdVerified: true,
          isBanned: true,
          banReason: true,
          isFlagged: true,
          violationCount: true,
          createdAt: true,
          lastActiveAt: true,
        },
      }),
      prisma.user.count({ where }),
    ]);

    const responseData = { 
      users, 
      total, 
      page: parseInt(page as string), 
      limit: parseInt(limit as string) 
    };
    await setCache(cacheKey, responseData, 300); // 5 minute TTL

    return res.status(200).json({ success: true, ...responseData });
  } catch (error: any) {
    console.error('Admin Get All Users Error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// BAN / UNBAN USER
// PATCH /api/admin/users/:id/ban
// ─────────────────────────────────────────────────────────────
export const banUser = async (req: Request, res: Response) => {
  try {
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const { id } = req.params;
    const { ban, reason } = req.body; // ban: boolean

    const user = await prisma.user.update({
      where: { id },
      data: {
        isBanned: ban,
        banReason: ban ? (reason || 'Banned by admin') : null,
      },
      select: { id: true, name: true, isBanned: true, banReason: true },
    });

    // Log the action
    const adminProfile = await prisma.adminProfile.findUnique({ where: { userId: req.user.userId } });
    if (adminProfile) {
      await prisma.adminLog.create({
        data: {
          adminProfileId: adminProfile.id,
          action: ban ? 'BANNED_USER' : 'UNBANNED_USER',
          targetType: 'User',
          targetId: id,
          note: reason || undefined,
        },
      });
    }

    // Invalidate user and log caches
    await Promise.all([
      deletePatternCache('admin:users:*'),
      deletePatternCache('admin:logs:*')
    ]);

    return res.status(200).json({ success: true, user, message: ban ? 'User banned' : 'User unbanned' });
  } catch (error: any) {
    console.error('Admin Ban User Error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// GET ALL PAYMENTS (Admin)
// GET /api/admin/payments?status=&page=1
// ─────────────────────────────────────────────────────────────
export const getAdminPayments = async (req: Request, res: Response) => {
  try {
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const { status, page = '1', limit = '20' } = req.query;
    const skip = (parseInt(page as string) - 1) * parseInt(limit as string);

    const cacheKey = `admin:payments:${status || 'all'}:${page}:${limit}`;
    const cached = await getCache<any>(cacheKey);
    if (cached) return res.status(200).json({ success: true, ...cached });

    const where: any = {};
    if (status && status !== 'ALL') where.status = status;

    const [payments, total, paymentStats, platformEarningStats] = await Promise.all([
      prisma.payment.findMany({
        where,
        skip,
        take: parseInt(limit as string),
        orderBy: { createdAt: 'desc' },
        include: {
          contract: {
            include: {
              project: { select: { id: true, title: true } },
              freelancerProfile: { include: { user: { select: { name: true } } } },
            },
          },
          milestone: { select: { title: true } },
        },
      }),
      prisma.payment.count({ where }),
      prisma.payment.groupBy({
        by: ['status'],
        _sum: { amount: true },
        _count: { id: true },
      }),
      prisma.platformEarning.aggregate({
        _sum: { amount: true }
      })
    ]);

    const formattedStats = {
      totalReleased: 0,
      totalInEscrow: 0,
      totalPending: 0,
      totalRefunded: 0,
    };
    paymentStats.forEach(s => {
      if (s.status === 'RELEASED') formattedStats.totalReleased = s._sum.amount || 0;
      if (s.status === 'HELD_IN_ESCROW') formattedStats.totalInEscrow = s._sum.amount || 0;
      if (s.status === 'PENDING') formattedStats.totalPending = s._sum.amount || 0;
      if (s.status === 'REFUNDED') formattedStats.totalRefunded = s._sum.amount || 0;
    });

    const responseData = { 
      payments, 
      total, 
      stats: {
        ...formattedStats,
        platformRevenue: platformEarningStats._sum.amount || 0
      } 
    };
    await setCache(cacheKey, responseData, 300);

    return res.status(200).json({ success: true, ...responseData });
  } catch (error: any) {
    console.error('Admin Get Payments Error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// GET ALL WITHDRAWALS (Admin)
// GET /api/admin/withdrawals?status=&page=1
// ─────────────────────────────────────────────────────────────
export const getAdminWithdrawals = async (req: Request, res: Response) => {
  try {
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const { status, page = '1', limit = '20' } = req.query;
    const skip = (parseInt(page as string) - 1) * parseInt(limit as string);

    const cacheKey = `admin:withdrawals:${status || 'all'}:${page}:${limit}`;
    const cached = await getCache<any>(cacheKey);
    if (cached) return res.status(200).json({ success: true, ...cached });

    const where: any = {};
    if (status && status !== 'ALL') where.status = status;

    const [withdrawals, total] = await Promise.all([
      prisma.withdrawal.findMany({
        where,
        skip,
        take: parseInt(limit as string),
        orderBy: { requestedAt: 'desc' },
        include: {
          freelancerProfile: {
            include: { user: { select: { id: true, name: true, email: true, profileImage: true } } },
          },
        },
      }),
      prisma.withdrawal.count({ where }),
    ]);

    const responseData = { withdrawals, total };
    await setCache(cacheKey, responseData, 300);

    return res.status(200).json({ success: true, ...responseData });
  } catch (error: any) {
    console.error('Admin Get Withdrawals Error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// GET ADMIN LOGS
// GET /api/admin/logs?page=1
// ─────────────────────────────────────────────────────────────
export const getAdminLogs = async (req: Request, res: Response) => {
  try {
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const { page = '1', limit = '30', targetType, startDate, endDate } = req.query;
    const skip = (parseInt(page as string) - 1) * parseInt(limit as string);

    const cacheKey = `admin:logs:${targetType || 'all'}:${startDate || ''}:${endDate || ''}:${page}:${limit}`;
    const cached = await getCache<any>(cacheKey);
    if (cached) return res.status(200).json({ success: true, ...cached });

    const where: any = {};
    if (targetType && targetType !== 'ALL') where.targetType = targetType;

    if (startDate || endDate) {
      where.createdAt = {};
      if (startDate) where.createdAt.gte = new Date(`${startDate}T00:00:00.000Z`);
      if (endDate) where.createdAt.lte = new Date(`${endDate}T23:59:59.999Z`);
    }

    const [logs, total] = await Promise.all([
      prisma.adminLog.findMany({
        where,
        skip,
        take: parseInt(limit as string),
        orderBy: { createdAt: 'desc' },
        include: {
          adminProfile: {
            include: { user: { select: { name: true, profileImage: true } } },
          },
        },
      }),
      prisma.adminLog.count({ where }),
    ]);

    const respData = { logs, total };
    await setCache(cacheKey, respData, 300);

    return res.status(200).json({ success: true, ...respData });
  } catch (error: any) {
    console.error('Admin Get Logs Error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// GET PLATFORM SETTINGS
// GET /api/admin/settings
// ─────────────────────────────────────────────────────────────
export const getPlatformSettings = async (req: Request, res: Response) => {
  try {
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const settings = await prisma.platformSetting.findMany({ orderBy: { key: 'asc' } });
    
    return res.status(200).json({ success: true, settings });
  } catch (error: any) {
    console.error('Admin Get Settings Error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// UPSERT PLATFORM SETTING
// PUT /api/admin/settings
// ─────────────────────────────────────────────────────────────
export const upsertPlatformSetting = async (req: Request, res: Response) => {
  try {
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const { key, value } = req.body;
    if (!key || value === undefined) {
      return res.status(400).json({ success: false, message: 'key and value are required' });
    }
    const setting = await prisma.platformSetting.upsert({
      where: { key },
      update: { value: String(value) },
      create: { key, value: String(value) },
    });

    // Log the action
    const adminProfile = await prisma.adminProfile.findUnique({ where: { userId: req.user.userId } });
    if (adminProfile) {
      await prisma.adminLog.create({
        data: {
          adminProfileId: adminProfile.id,
          action: 'UPDATE_PLATFORM_SETTING',
          targetType: 'Setting',
          targetId: setting.id,
          note: `${key} = ${value}`,
        },
      });
    }

    return res.status(200).json({ success: true, setting });
  } catch (error: any) {
    console.error('Admin Upsert Setting Error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// GRANT / DEDUCT TOKENS
// POST /api/admin/tokens/grant
// ─────────────────────────────────────────────────────────────
export const grantTokens = async (req: Request, res: Response) => {
  try {
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const { userId, amount, type, note } = req.body; // type: 'CREDIT' | 'DEBIT'
    if (!userId || !amount || !type) {
      return res.status(400).json({ success: false, message: 'userId, amount, type required' });
    }

    const freelancerProfile = await prisma.freelancerProfile.findUnique({ where: { userId } });
    if (!freelancerProfile) {
      return res.status(404).json({ success: false, message: 'Freelancer profile not found' });
    }

    const delta = type === 'CREDIT' ? amount : -amount;
    const newBalance = freelancerProfile.skillTokenBalance + delta;
    if (newBalance < 0) {
      return res.status(400).json({ success: false, message: 'Insufficient token balance' });
    }

    await prisma.$transaction([
      prisma.freelancerProfile.update({
        where: { userId },
        data: { skillTokenBalance: newBalance },
      }),
      prisma.tokenTransaction.create({
        data: {
          freelancerProfileId: freelancerProfile.id,
          type,
          reason: type === 'CREDIT' ? 'ADMIN_GRANT' : 'ADMIN_DEDUCT',
          amount,
          balanceAfter: newBalance,
          description: note || `Admin ${type === 'CREDIT' ? 'granted' : 'deducted'} ${amount} tokens`,
        },
      }),
    ]);

    // Log action
    const adminProfile = await prisma.adminProfile.findUnique({ where: { userId: req.user.userId } });
    if (adminProfile) {
      await prisma.adminLog.create({
        data: {
          adminProfileId: adminProfile.id,
          action: type === 'CREDIT' ? 'GRANT_TOKENS' : 'DEDUCT_TOKENS',
          targetType: 'User',
          targetId: userId,
          note: `${type === 'CREDIT' ? '+' : '-'}${amount} tokens. ${note || ''}`,
        },
      });
    }

    return res.status(200).json({ success: true, newBalance, message: `Tokens ${type === 'CREDIT' ? 'granted' : 'deducted'} successfully` });
  } catch (error: any) {
    console.error('Admin Grant Tokens Error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// ADMIN ANALYTICS OVERVIEW
// GET /api/admin/analytics
// ─────────────────────────────────────────────────────────────
export const getAdminAnalytics = async (req: Request, res: Response) => {
  try {
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }

    const now = new Date();
    const months: { label: string; start: Date; end: Date }[] = [];
    for (let i = 5; i >= 0; i--) {
      const start = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const end = new Date(now.getFullYear(), now.getMonth() - i + 1, 0, 23, 59, 59);
      months.push({
        label: start.toLocaleString('default', { month: 'short' }),
        start,
        end,
      });
    }

    const monthlyData = await Promise.all(
      months.map(async (m) => {
        const [users, projects, revenue] = await Promise.all([
          prisma.user.count({ where: { createdAt: { gte: m.start, lte: m.end } } }),
          prisma.project.count({ where: { createdAt: { gte: m.start, lte: m.end } } }),
          prisma.platformEarning.aggregate({
            _sum: { amount: true },
            where: { createdAt: { gte: m.start, lte: m.end } },
          }),
        ]);
        return {
          month: m.label,
          users,
          projects,
          revenue: revenue._sum.amount || 0,
        };
      })
    );

    // Category distribution
    const categoryStats = await prisma.project.groupBy({
      by: ['categoryId'],
      _count: { id: true },
      where: { categoryId: { not: null } },
      orderBy: { _count: { id: 'desc' } },
      take: 10,
    });

    const categoryIds = categoryStats.map(c => c.categoryId!).filter(Boolean);
    const categoryNames = await prisma.category.findMany({
      where: { id: { in: categoryIds } },
      select: { id: true, name: true },
    });
    const catMap = new Map(categoryNames.map(c => [c.id, c.name]));

    const categoryDistribution = categoryStats.map(c => ({
      name: catMap.get(c.categoryId!) || 'Unknown',
      count: c._count.id,
    }));

    // User role distribution
    const roleStats = await prisma.user.groupBy({
      by: ['role'],
      _count: { id: true },
      where: { role: { not: null } },
    });

    const roleDistribution = roleStats.map(r => ({
      role: r.role,
      count: r._count.id,
    }));

    // Project status distribution
    const projectStatusStats = await prisma.project.groupBy({
      by: ['status'],
      _count: { id: true },
    });

    return res.status(200).json({
      success: true,
      data: {
        monthlyData,
        categoryDistribution,
        roleDistribution,
        projectStatusDistribution: projectStatusStats.map(s => ({ status: s.status, count: s._count.id })),
      },
    });
  } catch (error: any) {
    console.error('Admin Analytics Error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// GET ALL PROJECTS (Admin)
// GET /api/admin/projects?status=&search=&page=1
// ─────────────────────────────────────────────────────────────
export const getAdminProjects = async (req: Request, res: Response) => {
  try {
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const { status, search, page = '1', limit = '20' } = req.query;
    const skip = (parseInt(page as string) - 1) * parseInt(limit as string);

    const cacheKey = `admin:projects:${status}:${search}:${page}:${limit}`;
    const cachedData = await getCache<any>(cacheKey);
    if (cachedData) {
      return res.status(200).json({ success: true, ...cachedData });
    }

    const where: any = {};
    if (status && status !== 'ALL') where.status = status;
    if (search) {
      where.OR = [
        { title: { contains: search as string, mode: 'insensitive' } },
        { description: { contains: search as string, mode: 'insensitive' } },
      ];
    }

    const [projects, total] = await Promise.all([
      prisma.project.findMany({
        where,
        skip,
        take: parseInt(limit as string),
        orderBy: { createdAt: 'desc' },
        include: {
          clientProfile: {
            include: { user: { select: { id: true, name: true, email: true } } },
          },
          category: { select: { name: true } },
          _count: { select: { proposals: true } },
        },
      }),
      prisma.project.count({ where }),
    ]);

    // Format for frontend
    const formatted = projects.map(p => ({
      id: p.id,
      title: p.title,
      status: p.status,
      budget: p.budget,
      budgetType: p.budgetType,
      size: p.size,
      proposalCount: p._count.proposals,
      createdAt: p.createdAt,
      clientProfile: {
        user: { 
          id: p.clientProfile.user.id, // helpful for linking
          name: p.clientProfile.user.name, 
          email: p.clientProfile.user.email 
        }
      },
      category: p.category,
    }));

    const responseData = { projects: formatted, total };
    await setCache(cacheKey, responseData, 300);

    return res.status(200).json({ success: true, ...responseData });
  } catch (error: any) {
    console.error('Admin Get Projects Error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// UPDATE PROJECT STATUS (Moderation)
// PATCH /api/admin/projects/:id/status
// ─────────────────────────────────────────────────────────────
export const updateProjectStatusByAdmin = async (req: Request, res: Response) => {
  try {
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const { id } = req.params;
    const { status, note } = req.body;

    const project = await prisma.project.update({
      where: { id },
      data: { status },
      include: { clientProfile: { select: { userId: true } } }
    });

    // Log the action
    const adminProfile = await prisma.adminProfile.findUnique({ where: { userId: req.user.userId } });
    if (adminProfile) {
      await prisma.adminLog.create({
        data: {
          adminProfileId: adminProfile.id,
          action: 'MODERATED_PROJECT',
          targetType: 'Project',
          targetId: id,
          note: `Status changed to ${status}. ${note || ''}`,
        },
      });
    }

    await Promise.all([
      deletePatternCache('admin:projects:*'),
      deletePatternCache('admin:payments:*'),
      deletePatternCache('admin:logs:*')
    ]);

    return res.status(200).json({ success: true, project, message: 'Project status updated' });
  } catch (error: any) {
    console.error('Admin Moderate Project Error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ─────────────────────────────────────────────────────────────
// PERMANENTLY DELETE PROJECT (Moderation)
// DELETE /api/admin/projects/:id
// ─────────────────────────────────────────────────────────────
export const deleteProjectByAdmin = async (req: Request, res: Response) => {
  try {
    if (req.user?.role !== 'ADMIN') {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const { id } = req.params;

    const project = await prisma.project.delete({
      where: { id },
    });

    // Log the action
    const adminProfile = await prisma.adminProfile.findUnique({ where: { userId: req.user.userId } });
    if (adminProfile) {
      await prisma.adminLog.create({
        data: {
          adminProfileId: adminProfile.id,
          action: 'DELETED_PROJECT',
          targetType: 'Project',
          targetId: id,
          note: `Project '${project.title}' permanently deleted.`,
        },
      });
    }

    await deletePatternCache('admin:projects:*');

    return res.status(200).json({ success: true, message: 'Project permanently deleted' });
  } catch (error: any) {
    console.error('Admin Delete Project Error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};


