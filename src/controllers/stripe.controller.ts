import { Request, Response } from 'express'
import Stripe from 'stripe'
import { prisma } from '../config/prisma'
import * as notificationService from '../services/notification.service'

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2026-03-25.dahlia',
})

// ─────────────────────────────────────────────────────────────
// CREATE PAYMENT INTENT (Client — before charging card)
// POST /api/stripe/create-payment-intent
// Body: { contractId, milestoneId }
// ─────────────────────────────────────────────────────────────
export const createPaymentIntent = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { contractId, milestoneId } = req.body

    if (!contractId || !milestoneId) {
      return res.status(400).json({ success: false, message: 'contractId and milestoneId are required.' })
    }

    // Load contract + milestone with access check
    const contract = await prisma.contract.findUnique({
      where: { id: contractId },
      include: {
        milestones: true,
        project: {
          include: { clientProfile: { select: { userId: true, fullName: true } } }
        }
      }
    })

    if (!contract) {
      return res.status(404).json({ success: false, message: 'Contract not found.' })
    }
    if (contract.project.clientProfile.userId !== userId) {
      return res.status(403).json({ success: false, message: 'Not authorized.' })
    }

    const milestone = contract.milestones.find((m: any) => m.id === milestoneId)
    if (!milestone) {
      return res.status(404).json({ success: false, message: 'Milestone not found.' })
    }
    if (milestone.status !== 'PENDING') {
      return res.status(400).json({
        success: false,
        message: `Milestone cannot be funded in "${milestone.status}" status.`
      })
    }

    // Enforce sequential funding — no PENDING milestone before this one
    const pendingBefore = contract.milestones.filter(
      (m: any) => m.order < milestone.order && m.status === 'PENDING'
    )
    if (pendingBefore.length > 0) {
      return res.status(400).json({ success: false, message: 'Please fund milestones in order.' })
    }

    // Amount in cents (Stripe requires integer cents)
    const amountInCents = Math.round(milestone.amount * 100)

    const paymentIntent = await stripe.paymentIntents.create({
      amount: amountInCents,
      currency: 'usd',
      payment_method_types: ['card'],
      metadata: {
        contractId,
        milestoneId,
        milestoneTitle: milestone.title,
        clientUserId: userId,
      },
      description: `SkillBridge Escrow — Milestone: "${milestone.title}"`,
    })

    return res.status(200).json({
      success: true,
      clientSecret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id,
      amount: milestone.amount,
      milestoneTitle: milestone.title,
    })
  } catch (error: any) {
    console.error('Create payment intent error:', error)
    return res.status(500).json({ success: false, message: error.message || 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────
// CONFIRM FUND AFTER SUCCESSFUL STRIPE PAYMENT
// POST /api/stripe/confirm-fund
// Body: { contractId, milestoneId, paymentIntentId }
// ─────────────────────────────────────────────────────────────
export const confirmFundMilestone = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { contractId, milestoneId, paymentIntentId } = req.body

    if (!contractId || !milestoneId || !paymentIntentId) {
      return res.status(400).json({ success: false, message: 'contractId, milestoneId and paymentIntentId are required.' })
    }

    // Verify payment with Stripe
    const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId)

    if (paymentIntent.status !== 'succeeded') {
      return res.status(400).json({
        success: false,
        message: `Payment not completed. Stripe status: ${paymentIntent.status}`
      })
    }

    // Validate metadata matches — prevent fraud / replay attacks
    if (
      paymentIntent.metadata.contractId !== contractId ||
      paymentIntent.metadata.milestoneId !== milestoneId ||
      paymentIntent.metadata.clientUserId !== userId
    ) {
      return res.status(403).json({ success: false, message: 'Payment intent metadata mismatch.' })
    }

    // Load contract with access check
    const contract = await prisma.contract.findUnique({
      where: { id: contractId },
      include: {
        milestones: { orderBy: { order: 'asc' } },
        freelancerProfile: { include: { user: { select: { name: true } } } },
        project: {
          include: { clientProfile: { select: { userId: true, fullName: true } } }
        }
      }
    })

    if (!contract) {
      return res.status(404).json({ success: false, message: 'Contract not found.' })
    }
    if (contract.project.clientProfile.userId !== userId) {
      return res.status(403).json({ success: false, message: 'Not authorized.' })
    }

    const milestone = contract.milestones.find((m: any) => m.id === milestoneId)
    if (!milestone) {
      return res.status(404).json({ success: false, message: 'Milestone not found.' })
    }

    // Idempotency — if already funded (e.g., duplicate webhook), skip
    if (milestone.status !== 'PENDING') {
      return res.status(200).json({ success: true, message: 'Milestone already funded.' })
    }

    // Check if a payment record already exists for this paymentIntent
    const existingPayment = await prisma.payment.findFirst({
      where: { transactionId: paymentIntentId }
    })
    if (existingPayment) {
      return res.status(200).json({ success: true, message: 'Payment already recorded.' })
    }

    await prisma.$transaction(async (tx) => {
      // Mark milestone FUNDED
      await tx.milestone.update({
        where: { id: milestoneId },
        data: {
          status: 'FUNDED',
          history: [
            {
              type: 'FUNDED',
              timestamp: new Date(),
              content: `Milestone funded via Stripe. $${milestone.amount.toLocaleString()} is now held in escrow.`,
              actorName: contract.project.clientProfile.fullName,
              actorRole: 'CLIENT'
            }
          ]
        }
      })

      // Create real payment record linked to Stripe PaymentIntent
      await tx.payment.create({
        data: {
          contractId,
          milestoneId,
          amount: milestone.amount,
          status: 'HELD_IN_ESCROW',
          transactionId: paymentIntentId,
          paidAt: new Date(),
        }
      })

      // Notify freelancer
      await notificationService.createNotification({
        userId: contract.freelancerProfile.userId,
        type: 'PAYMENT_RELEASED',
        title: 'Milestone Funded! 💰',
        body: `Client has funded "${milestone.title}" — $${milestone.amount.toFixed(2)} is now in escrow. You can start work!`,
        link: `/freelancer/contracts/${contractId}`,
      }, tx)
    })

    return res.status(200).json({
      success: true,
      message: 'Milestone funded successfully via Stripe! Freelancer can now start work.'
    })
  } catch (error: any) {
    console.error('Confirm fund milestone error:', error)
    return res.status(500).json({ success: false, message: error.message || 'Internal server error.' })
  }
}
