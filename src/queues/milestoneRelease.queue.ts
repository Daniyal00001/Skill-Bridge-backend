import { Queue } from 'bullmq'
import IORedis from 'ioredis'

// ── IORedis connection for BullMQ ─────────────────────────────
export const redisConnection = new IORedis(process.env.REDIS_URL || 'redis://localhost:6379', {
  maxRetriesPerRequest: null, // Required by BullMQ
})

// ── Queue definition ──────────────────────────────────────────
export const milestoneReleaseQueue = new Queue('milestone-auto-release', {
  connection: redisConnection,
  defaultJobOptions: {
    removeOnComplete: true,
    removeOnFail: 500, // keep last 500 failed jobs for debugging
  },
})

// ── 72-hour auto-release delay constant ──────────────────────
export const AUTO_RELEASE_DELAY_MS = 72 * 60 * 60 * 1000 // 72 hours

/**
 * Schedules a delayed job to auto-release a milestone payment.
 *
 * @param milestoneId  The milestone to auto-approve
 * @param contractId   The contract it belongs to
 * @param delayMs      Delay in milliseconds (default: 72h)
 */
export async function scheduleMilestoneAutoRelease(
  milestoneId: string,
  contractId: string,
  delayMs: number = AUTO_RELEASE_DELAY_MS
): Promise<void> {
  await milestoneReleaseQueue.add(
    'auto-release',
    { milestoneId, contractId },
    {
      delay: delayMs,
      jobId: `auto-release-${milestoneId}`, // deduplicate: one job per milestone
    }
  )
  console.log(
    `⏰ Auto-release job scheduled for milestone ${milestoneId} in ${delayMs / 1000}s`
  )
}
