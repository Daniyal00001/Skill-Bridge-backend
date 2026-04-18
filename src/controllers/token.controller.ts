import { Request, Response } from 'express'
import { prisma } from '../config/prisma'
import Stripe from 'stripe'

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2026-03-25.dahlia',
})

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
      select: { id: true, skillTokenBalance: true, balance: true }
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

    // Compute token summary stats
    const totalEarned = transactions
      .filter(t => t.type === 'CREDIT')
      .reduce((sum, t) => sum + t.amount, 0)
    const totalSpent = transactions
      .filter(t => t.type === 'DEBIT')
      .reduce((sum, t) => sum + t.amount, 0)

    // ── Self-healing money balance ────────────────────────────────────────
    // If stored balance is 0, recalculate from released payments minus withdrawals.
    // This handles accounts where the balance field was never updated correctly.
    let moneyBalance = profile.balance
    if (moneyBalance <= 0) {
      try {
        const [earningsAgg, withdrawalsAgg] = await Promise.all([
          prisma.payment.aggregate({
            where: { contract: { freelancerProfileId: profile.id }, status: 'RELEASED' },
            _sum: { amount: true }
          }),
          (prisma as any).withdrawal.aggregate({
            where: {
              freelancerProfileId: profile.id,
              status: { in: ['COMPLETED', 'PROCESSING'] }
            },
            _sum: { amount: true }
          }).catch(() => ({ _sum: { amount: 0 } }))
        ])
        const totalReleased = earningsAgg._sum.amount || 0
        const totalWithdrawn = withdrawalsAgg._sum.amount || 0
        moneyBalance = Math.max(0, totalReleased - totalWithdrawn)

        // Heal the stored balance if we found a discrepancy
        if (moneyBalance > 0 && profile.balance <= 0) {
          await prisma.freelancerProfile.update({
            where: { id: profile.id },
            data: { balance: moneyBalance }
          })
        }
      } catch {
        // Safe to ignore — fall back to stored value
      }
    }

    return res.status(200).json({
      success: true,
      balance: profile.skillTokenBalance,
      moneyBalance,
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

// ─────────────────────────────────────────────────────────────
// BUY TOKENS (Freelancer)
// POST /api/tokens/buy
// ─────────────────────────────────────────────────────────────
export const buyTokens = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { amountOfMoney } = req.body // How much money the freelancer is spending

    if (!amountOfMoney || isNaN(Number(amountOfMoney)) || Number(amountOfMoney) <= 0) {
      return res.status(400).json({ success: false, message: 'A valid positive amount of money is required.' })
    }

    const money = Number(amountOfMoney)

    const freelancer = await prisma.freelancerProfile.findUnique({
      where: { userId },
      select: { id: true, balance: true, skillTokenBalance: true }
    })

    if (!freelancer) {
      return res.status(404).json({ success: false, message: 'Freelancer profile not found.' })
    }

    if (freelancer.balance < money) {
      return res.status(400).json({ success: false, message: 'Insufficient balance to buy tokens.' })
    }

    const tokensToBuy = Math.floor(money * 10) // Rate: $1 = 10 SkillTokens
    
    if (tokensToBuy <= 0) {
      return res.status(400).json({ success: false, message: 'Amount is too small to purchase any tokens.' })
    }

    await prisma.$transaction(async (tx) => {
      // 1. Deduct money from freelancer balance and increment tokens
      await tx.freelancerProfile.update({
        where: { id: freelancer.id },
        data: {
          balance: { decrement: money },
          skillTokenBalance: { increment: tokensToBuy }
        }
      })

      // 2. Record Token Transaction (Credit)
      await tx.tokenTransaction.create({
        data: {
          freelancerProfileId: freelancer.id,
          type: 'CREDIT',
          reason: 'TOKEN_PURCHASE',
          amount: tokensToBuy,
          balanceAfter: freelancer.skillTokenBalance + tokensToBuy,
          description: `Purchased ${tokensToBuy} SkillTokens for $${money.toFixed(2)}`
        }
      })

      // 3. Record Platform Earning
      await tx.platformEarning.create({
        data: {
          amount: money,
          type: 'TOKEN_PURCHASE',
          description: `Freelancer purchased ${tokensToBuy} tokens`,
          metadata: {
            freelancerId: freelancer.id,
            tokensBought: tokensToBuy,
            cost: money
          }
        }
      })
    })

    return res.status(200).json({
      success: true,
      message: `Successfully purchased ${tokensToBuy} SkillTokens!`,
      newBalance: freelancer.skillTokenBalance + tokensToBuy,
      cost: money
    })
  } catch (error) {
    console.error('Buy tokens error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────
// CREATE PAYMENT INTENT FOR TOKENS (Card)
// POST /api/tokens/buy-with-card/intent
// ─────────────────────────────────────────────────────────────
export const createTokenPaymentIntent = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { amountOfMoney } = req.body

    if (!amountOfMoney || isNaN(Number(amountOfMoney)) || Number(amountOfMoney) < 1) {
      return res.status(400).json({ success: false, message: 'Minimum purchase is $1.00' })
    }

    const money = Number(amountOfMoney)
    const tokensToBuy = Math.floor(money * 10)

    // Fetch freelancer id (needed for raw MongoDB read)
    const freelancer = await prisma.freelancerProfile.findUnique({
      where: { userId },
      select: { id: true }
    })

    if (!freelancer) {
      return res.status(404).json({ success: false, message: 'Freelancer profile not found.' })
    }

    // Read stripeCustomerId via $runCommandRaw — field added after Prisma client generation
    const rawRead = await (prisma as any).$runCommandRaw({
      find: 'freelancer_profiles',
      filter: { _id: { $oid: freelancer.id } },
      projection: { stripeCustomerId: 1 },
      limit: 1
    })
    const stripeCustomerId: string | null =
      rawRead?.cursor?.firstBatch?.[0]?.stripeCustomerId ?? null

    const intentData: any = {
      amount: Math.round(money * 100),
      currency: 'usd',
      payment_method_types: ['card'],
      metadata: {
        userId,
        type: 'TOKEN_PURCHASE',
        tokensToBuy: tokensToBuy.toString(),
        moneyAmount: money.toString()
      },
      description: `Purchase of ${tokensToBuy} SkillTokens`,
    }

    // Attach Stripe customer if the freelancer has saved cards — enables saved-card payments
    if (stripeCustomerId) {
      intentData.customer = stripeCustomerId
    }

    const paymentIntent = await stripe.paymentIntents.create(intentData)

    return res.status(200).json({
      success: true,
      clientSecret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id,
      tokens: tokensToBuy,
      amount: money
    })
  } catch (error: any) {
    console.error('Token payment intent error:', error)
    return res.status(500).json({ success: false, message: error.message })
  }
}

// ─────────────────────────────────────────────────────────────
// CONFIRM TOKEN PURCHASE (Card)
// POST /api/tokens/buy-with-card/confirm
// ─────────────────────────────────────────────────────────────
export const confirmTokenCardPurchase = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { paymentIntentId } = req.body

    if (!paymentIntentId) {
      return res.status(400).json({ success: false, message: 'paymentIntentId is required.' })
    }

    const intent = await stripe.paymentIntents.retrieve(paymentIntentId)

    if (intent.status !== 'succeeded') {
      return res.status(400).json({ success: false, message: 'Payment not successful.' })
    }

    if (intent.metadata.userId !== userId || intent.metadata.type !== 'TOKEN_PURCHASE') {
      return res.status(403).json({ success: false, message: 'Invalid payment metadata.' })
    }

    const tokensToBuy = parseInt(intent.metadata.tokensToBuy)
    const money = parseFloat(intent.metadata.moneyAmount)

    const profile = await prisma.freelancerProfile.findUnique({
      where: { userId },
      select: { id: true, skillTokenBalance: true }
    })

    if (!profile) {
      return res.status(404).json({ success: false, message: 'Freelancer profile not found.' })
    }

    // Check if idempotent (already recorded)
    const existingTx = await prisma.tokenTransaction.findFirst({
      where: { description: { contains: paymentIntentId } }
    })

    if (existingTx) {
      return res.status(200).json({ success: true, message: 'Purchase already processed.' })
    }

    await prisma.$transaction(async (tx) => {
      // 1. Credit tokens
      await tx.freelancerProfile.update({
        where: { id: profile.id },
        data: { skillTokenBalance: { increment: tokensToBuy } }
      })

      // 2. Record Transaction
      await tx.tokenTransaction.create({
        data: {
          freelancerProfileId: profile.id,
          type: 'CREDIT',
          reason: 'TOKEN_PURCHASE',
          amount: tokensToBuy,
          balanceAfter: profile.skillTokenBalance + tokensToBuy,
          description: `Purchased ${tokensToBuy} SkillTokens via Card (Stripe ID: ${paymentIntentId})`
        }
      })

      // 3. Record Platform Earning
      await tx.platformEarning.create({
        data: {
          amount: money,
          type: 'TOKEN_PURCHASE',
          description: `Freelancer purchased ${tokensToBuy} tokens via Card`,
          metadata: {
            freelancerId: profile.id,
            tokensBought: tokensToBuy,
            paymentMethod: 'CARD',
            stripeId: paymentIntentId
          }
        }
      })
    })

    return res.status(200).json({
      success: true,
      message: `Successfully purchased ${tokensToBuy} SkillTokens!`,
      newBalance: profile.skillTokenBalance + tokensToBuy
    })

  } catch (error: any) {
    console.error('Confirm token purchase error:', error)
    return res.status(500).json({ success: false, message: error.message })
  }
}
