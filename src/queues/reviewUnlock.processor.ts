import { Job } from 'bull'
import { prisma } from '../config/prisma'
import { reviewUnlockQueue } from './reviewUnlock.queue'
import * as notificationService from '../services/notification.service'

interface ReviewUnlockJobData {
  contractId: string
}

/**
 * Helper: reveal all unrevealed reviews for a contract + update average ratings.
 */
async function revealContractReviews(contractId: string): Promise<void> {
  const now = new Date()

  // Fetch unrevealed reviews with full contract+profile data
  const reviews = await prisma.review.findMany({
    where: { contractId, isRevealed: false },
    include: {
      giver: { select: { name: true } },
      receiver: { select: { name: true } },
    },
  })

  if (reviews.length === 0) {
    console.log(`No unrevealed reviews for contract ${contractId} — skipping.`)
    return
  }

  // Reveal all reviews in one transaction
  await prisma.$transaction(async (tx) => {
    for (const review of reviews) {
      await tx.review.update({
        where: { id: review.id },
        data: { isRevealed: true, revealedAt: now },
      })

      // Notify the receiver that their review is now visible
      await notificationService.createNotification(
        {
          userId: review.receiverId,
          type: 'REVIEW_RECEIVED',
          title: 'Your review is now visible!',
          body: `${review.giver.name} left you a ${review.rating}-star review. You can now see it on your profile.`,
          link: `/freelancer/contracts/${contractId}`,
        },
        tx
      )
    }
  })

  // Recalculate average rating for each receiver
  const receiverIds = [...new Set(reviews.map((r) => r.receiverId))]
  for (const receiverId of receiverIds) {
    await recalculateAverageRating(receiverId)
  }

  console.log(`✅ Revealed ${reviews.length} review(s) for contract ${contractId}`)
}

/**
 * Recalculates averageRating + totalReviews for a user on their profile.
 * Works for both freelancer and client profiles.
 */
export async function recalculateAverageRating(userId: string): Promise<void> {
  const agg = await prisma.review.aggregate({
    where: { receiverId: userId, isRevealed: true },
    _avg: { rating: true },
    _count: { rating: true },
  })

  const avg = agg._avg.rating || 0
  const total = agg._count.rating || 0

  // Try freelancer profile first
  const freelancerProfile = await prisma.freelancerProfile.findUnique({
    where: { userId },
    select: { id: true },
  })

  if (freelancerProfile) {
    await prisma.freelancerProfile.update({
      where: { userId },
      data: { averageRating: avg, totalReviews: total },
    })
    return
  }

  // Fall back to client profile
  const clientProfile = await prisma.clientProfile.findUnique({
    where: { userId },
    select: { id: true },
  })

  if (clientProfile) {
    await prisma.clientProfile.update({
      where: { userId },
      data: { averageRating: avg, totalReviews: total },
    })
  }
}

/**
 * Processes the auto-unlock job:
 *  1. Find all unrevealed reviews for this contract
 *  2. Reveal them (even if only one party submitted)
 *  3. Update average ratings
 *  4. Send notifications
 */
async function processReviewAutoUnlock(job: Job<ReviewUnlockJobData>) {
  const { contractId } = job.data
  console.log(`🔄 Processing review auto-unlock for contract ${contractId}`)
  await revealContractReviews(contractId)
}

/**
 * Initializes the review unlock queue processor.
 * Call once at server startup.
 */
export function initReviewUnlockWorker() {
  reviewUnlockQueue.process(5, processReviewAutoUnlock)

  reviewUnlockQueue.on('completed', (job) => {
    console.log(`✅ Review unlock job ${job.id} completed.`)
  })

  reviewUnlockQueue.on('failed', (job, err) => {
    console.error(`❌ Review unlock job ${job.id} failed:`, err.message)
  })

  console.log('🚀 ReviewUnlock Worker initialized (Bull)')
}

// Export helper for direct use in review controller (instant unlock path)
export { revealContractReviews }
