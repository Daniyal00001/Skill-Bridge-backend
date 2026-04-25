import { Job } from 'bull'
import { prisma } from '../config/prisma'
import { milestoneReleaseQueue } from './milestoneRelease.queue'
import { createNotification } from '../services/notification.service'

interface AutoReleaseJobData {
  milestoneId: string
  contractId: string
}

/**
 * Processes the auto-release job:
 *  1. Fetch milestone + contract + payment
 *  2. Guard: milestone still SUBMITTED, payment still HELD_IN_ESCROW, no open dispute
 *  3. Release payment & approve milestone in a transaction
 *  4. Send notifications to both client and freelancer
 *  5. If all milestones approved → complete contract + project
 */
async function processAutoRelease(job: Job<AutoReleaseJobData>) {
  const { milestoneId, contractId } = job.data

  console.log(`🔄 Processing auto-release for milestone ${milestoneId}`)

  // ── 1. Fetch milestone with related data ────────────────────
  const milestone = await prisma.milestone.findUnique({
    where: { id: milestoneId },
    include: {
      contract: {
        include: {
          milestones: { select: { id: true, status: true } },
          payments: true,
          project: {
            include: {
              clientProfile: { select: { userId: true, fullName: true } },
              disputes: { select: { status: true } },
            },
          },
          freelancerProfile: {
            select: { userId: true },
          },
        },
      },
      payment: true,
    },
  })

  if (!milestone) {
    console.log(`⚠️  Milestone ${milestoneId} not found — skipping auto-release.`)
    return
  }

  // ── 2. Guard checks ─────────────────────────────────────────

  // Guard A: milestone must still be SUBMITTED
  if (milestone.status !== 'SUBMITTED') {
    console.log(
      `⏭️  Milestone ${milestoneId} is in status "${milestone.status}" — client already acted. Skipping.`
    )
    return
  }

  // Guard B: payment must still be HELD_IN_ESCROW
  const payment = milestone.payment
  if (!payment || payment.status !== 'HELD_IN_ESCROW') {
    console.log(
      `⏭️  Payment for milestone ${milestoneId} is not in escrow — skipping.`
    )
    return
  }

  // Guard C: no open dispute on the project
  const disputes = milestone.contract.project.disputes
  const hasOpenDispute = disputes.some(d => d.status === 'OPEN')
  if (hasOpenDispute) {
    console.log(
      `⏭️  Project has an open dispute — skipping auto-release for milestone ${milestoneId}.`
    )
    return
  }

  const contract = milestone.contract
  const clientUserId = contract.project.clientProfile.userId
  const freelancerUserId = contract.freelancerProfile.userId

  // ── 3. Release payment in a transaction ──────────────────────
  await prisma.$transaction(async (tx) => {
    // Mark milestone as APPROVED
    await tx.milestone.update({
      where: { id: milestoneId },
      data: {
        status: 'APPROVED',
        approvedAt: new Date(),
      },
    })

    // Release the escrow payment
    await tx.payment.update({
      where: { id: payment.id },
      data: {
        status: 'RELEASED',
        releasedAt: new Date(),
      },
    })

    // Calculate 10% platform fee
    const platformFee = milestone.amount * 0.10
    const freelancerNet = milestone.amount - platformFee

    // Credit freelancer balance (net amount after 10% fee)
    await tx.freelancerProfile.update({
      where: { userId: freelancerUserId },
      data: { balance: { increment: freelancerNet } }
    })

    // Record Platform Earning
    await tx.platformEarning.create({
      data: {
        amount: platformFee,
        type: 'PROJECT_FEE',
        description: `10% fee from auto-released milestone "${milestone.title}" on contract ${contractId}`,
        metadata: {
          contractId,
          milestoneId,
          freelancerId: contract.freelancerProfileId,
          grossAmount: milestone.amount,
          feePercentage: 10,
          feeAmount: platformFee,
          netAmount: freelancerNet,
          isAutoRelease: true
        }
      }
    })



    // ── 4. Notifications ──────────────────────────────────────

    // Notify freelancer — payment released
    await createNotification({
      userId: freelancerUserId,
      type: 'PAYMENT_RELEASED',
      title: 'Payment Auto-Released!',
      body: `"${milestone.title}" was automatically approved after 3 days of review. $${milestone.amount.toFixed(2)} has been released to you.`,
      link: `/freelancer/contracts/${contractId}`,
    }, tx)

    // Notify client — auto-approved
    await createNotification({
      userId: clientUserId,
      type: 'MILESTONE_APPROVED',
      title: 'Milestone Auto-Approved',
      body: `"${milestone.title}" was automatically approved and payment released after 72 hours without a response. If you have concerns, please open a dispute.`,
      link: `/client/contracts/${contractId}`,
    }, tx)

    // Audit log — system alert to client
    await createNotification({
      userId: clientUserId,
      type: 'SYSTEM_ALERT',
      title: 'Auto-Release Audit',
      body: `System auto-released $${milestone.amount.toFixed(2)} for milestone "${milestone.title}" on contract ${contractId} at ${new Date().toISOString()}.`,
      link: `/client/contracts/${contractId}`,
    }, tx)
  })

  console.log(`✅ Auto-released payment for milestone ${milestoneId}`)

  // ── 5. Check if all milestones are approved ──────────────────
  // Refresh milestones from DB (the one we just approved is now APPROVED)
  const updatedMilestones = await prisma.milestone.findMany({
    where: { contractId },
    select: { id: true, status: true },
  })

  const allApproved = updatedMilestones.every((m) => m.status === 'APPROVED')

  if (allApproved) {
    await prisma.$transaction(async (tx) => {
      await tx.contract.update({
        where: { id: contractId },
        data: { status: 'COMPLETED', endDate: new Date() },
      })

      await tx.project.update({
        where: { id: contract.projectId },
        data: { status: 'COMPLETED' },
      })

          await createNotification({
            userId: freelancerUserId,
            type: 'MILESTONE_APPROVED',
            title: 'Contract Completed!',
            body: `All milestones approved! Your contract for "${contract.project.title}" is now complete.`,
            link: `/freelancer/contracts/${contractId}`,
          }, tx)

          await createNotification({
            userId: clientUserId,
            type: 'MILESTONE_APPROVED',
            title: 'Contract Completed!',
            body: `All milestones have been approved and payment released for "${contract.project.title}". The contract is now complete.`,
            link: `/client/contracts/${contractId}`,
          }, tx)
    })

    console.log(`🏁 Contract ${contractId} marked as COMPLETED — all milestones approved.`)
  }
}

/**
 * Initializes and starts the BullMQ Worker for auto-release jobs.
 * Call this once at server startup.
 */
export function initMilestoneReleaseWorker() {
  milestoneReleaseQueue.process(5, processAutoRelease)

  milestoneReleaseQueue.on('completed', (job, result) => {
    console.log(`✅ Auto-release job ${job.id} completed.`)
  })

  milestoneReleaseQueue.on('failed', (job, err) => {
    console.error(`❌ Auto-release job ${job.id} failed:`, err.message)
  })

  console.log('🚀 MilestoneRelease Worker initialized (Bull)')
}
