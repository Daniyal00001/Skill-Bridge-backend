import { Request, Response } from 'express'
import { prisma } from '../config/prisma'

// ─────────────────────────────────────────────────────────────
// GET MY TOKEN BALANCE
// GET /api/tokens/balance
// ─────────────────────────────────────────────────────────────
export const getMyTokenBalance = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId

    const profile = await prisma.freelancerProfile.findUnique({
      where: { userId },
      select: { skillTokenBalance: true }
    })

    if (!profile) {
      return res.status(404).json({ success: false, message: 'Freelancer profile not found.' })
    }

    return res.status(200).json({
      success: true,
      balance: profile.skillTokenBalance,
      tokenName: 'SkillTokens',
    })
  } catch (error) {
    console.error('Get token balance error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────
// GET MY TOKEN HISTORY
// GET /api/tokens/history
// ─────────────────────────────────────────────────────────────
export const getMyTokenHistory = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { page = 1, limit = 20 } = req.query

    const pageNum = Number(page)
    const limitNum = Number(limit)
    const skip = (pageNum - 1) * limitNum

    const profile = await prisma.freelancerProfile.findUnique({
      where: { userId },
      select: { id: true, skillTokenBalance: true }
    })

    if (!profile) {
      return res.status(404).json({ success: false, message: 'Freelancer profile not found.' })
    }

    const [transactions, total] = await Promise.all([
      prisma.tokenTransaction.findMany({
        where: { freelancerProfileId: profile.id },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limitNum,
      }),
      prisma.tokenTransaction.count({ where: { freelancerProfileId: profile.id } })
    ])

    // Compute summary stats
    const totalEarned = transactions
      .filter(t => t.type === 'CREDIT')
      .reduce((sum, t) => sum + t.amount, 0)
    const totalSpent = transactions
      .filter(t => t.type === 'DEBIT')
      .reduce((sum, t) => sum + t.amount, 0)

    return res.status(200).json({
      success: true,
      balance: profile.skillTokenBalance,
      tokenName: 'SkillTokens',
      totalEarned,
      totalSpent,
      transactions,
      pagination: {
        total,
        page: pageNum,
        limit: limitNum,
        totalPages: Math.ceil(total / limitNum)
      }
    })
  } catch (error) {
    console.error('Get token history error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}
