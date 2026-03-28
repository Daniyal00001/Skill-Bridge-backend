import Queue from 'bull'

// ── Queue definition ──────────────────────────────────────────
export const reviewUnlockQueue = new Queue(
  'review-auto-unlock',
  process.env.REDIS_URL || 'redis://localhost:6379',
  {
    defaultJobOptions: {
      removeOnComplete: true,
      removeOnFail: 500,
    },
  }
)

// 7 days in ms
export const REVIEW_DEADLINE_MS = 7 * 24 * 60 * 60 * 1000

/**
 * Schedules a delayed job to auto-unlock reviews for a contract.
 * Job is deduplicated by contractId — only one job per contract.
 */
export async function scheduleReviewAutoUnlock(
  contractId: string,
  delayMs: number = REVIEW_DEADLINE_MS
): Promise<void> {
  await reviewUnlockQueue.add(
    { contractId },
    {
      delay: delayMs,
      jobId: `review-unlock-${contractId}`, // deduplicate
    }
  )
  console.log(
    `⏰ Review auto-unlock job scheduled for contract ${contractId} in ${delayMs / 1000 / 3600}h`
  )
}

/**
 * Removes the scheduled auto-unlock job for a contract.
 * Called when BOTH parties submit — no need to wait anymore.
 */
export async function cancelReviewAutoUnlock(contractId: string): Promise<void> {
  const job = await reviewUnlockQueue.getJob(`review-unlock-${contractId}`)
  if (job) {
    await job.remove()
    console.log(`🗑️  Cancelled review auto-unlock job for contract ${contractId}`)
  }
}
