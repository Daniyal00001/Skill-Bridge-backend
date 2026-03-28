import { Request, Response } from 'express'
import { prisma } from '../config/prisma'
import * as notificationService from '../services/notification.service'
import {
  revealContractReviews,
  recalculateAverageRating,
} from '../queues/reviewUnlock.processor'
import {
  scheduleReviewAutoUnlock,
  cancelReviewAutoUnlock,
  reviewUnlockQueue,
} from '../queues/reviewUnlock.queue'

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/reviews — Submit a blind review
// ─────────────────────────────────────────────────────────────────────────────
export const submitReview = async (req: Request, res: Response) => {
  try {
    const giverId = (req as any).user?.userId
    const { contractId, rating, comment } = req.body

    // Validate rating
    const ratingNum = Number(rating)
    if (!ratingNum || ratingNum < 1 || ratingNum > 5) {
      return res.status(400).json({ success: false, message: 'Rating must be between 1 and 5.' })
    }

    // 1. Fetch contract with both profiles
    const contract = await prisma.contract.findUnique({
      where: { id: contractId },
      include: {
        project: {
          include: {
            clientProfile: { select: { userId: true, fullName: true } },
          },
        },
        freelancerProfile: { select: { userId: true, fullName: true } },
      },
    })

    if (!contract) {
      return res.status(404).json({ success: false, message: 'Contract not found.' })
    }

    if (contract.status !== 'COMPLETED') {
      return res.status(400).json({ success: false, message: 'Reviews can only be submitted for completed contracts.' })
    }

    // 2. Determine giver role + receiver
    const clientUserId = contract.project.clientProfile.userId
    const freelancerUserId = contract.freelancerProfile.userId

    let receiverId: string
    let giverRole: 'CLIENT' | 'FREELANCER'

    if (giverId === clientUserId) {
      receiverId = freelancerUserId
      giverRole = 'CLIENT'
    } else if (giverId === freelancerUserId) {
      receiverId = clientUserId
      giverRole = 'FREELANCER'
    } else {
      return res.status(403).json({ success: false, message: 'You are not part of this contract.' })
    }

    // 3. Calculate review deadline (7 days from now)
    const reviewDeadline = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)

    // 4. Create review (blind by default)
    const review = await prisma.review.create({
      data: {
        contractId,
        giverId,
        receiverId,
        rating: ratingNum,
        comment: comment?.trim() || null,
        isRevealed: false,
        giverRole,
        reviewDeadline,
      },
    })

    // 5. Check if BOTH reviews now exist for this contract
    const allReviews = await prisma.review.findMany({
      where: { contractId },
    })

    if (allReviews.length >= 2) {
      // ✅ Both submitted — unlock instantly + cancel the delayed job
      await revealContractReviews(contractId)
      await cancelReviewAutoUnlock(contractId)

      // Recalculate average for both parties
      await recalculateAverageRating(clientUserId)
      await recalculateAverageRating(freelancerUserId)

      // Notify both
      await notificationService.createNotification({
        userId: clientUserId,
        type: 'REVIEW_UNLOCKED',
        title: 'Reviews are now visible!',
        body: `Both reviews for the project have been submitted and are now visible.`,
        link: `/client/contracts/${contractId}`,
      })
      await notificationService.createNotification({
        userId: freelancerUserId,
        type: 'REVIEW_UNLOCKED',
        title: 'Reviews are now visible!',
        body: `Both reviews for the project have been submitted and are now visible.`,
        link: `/freelancer/contracts/${contractId}`,
      })

      return res.status(201).json({
        success: true,
        message: 'Review submitted! Both reviews are now visible.',
        reviewStatus: 'BOTH_REVEALED',
        review,
      })
    }

    // ⏳ Only one review so far — schedule the deadline job (idempotent: jobId deduplicates)
    // Only schedule if no existing job (first submitter triggers it)
    const existingJob = await reviewUnlockQueue.getJob(
      `review-unlock-${contractId}`
    )
    if (!existingJob) {
      await scheduleReviewAutoUnlock(contractId)
    }

    // Notify the OTHER party to leave a review
    const otherUserId = giverId === clientUserId ? freelancerUserId : clientUserId
    const otherLink = giverId === clientUserId
      ? `/freelancer/contracts/${contractId}`
      : `/client/contracts/${contractId}`

    await notificationService.createNotification({
      userId: otherUserId,
      type: 'REVIEW_RECEIVED',
      title: 'Leave a review!',
      body: `Your contract has been completed. Leave a review before the deadline — you have 7 days.`,
      link: otherLink,
    })

    return res.status(201).json({
      success: true,
      message: 'Review submitted! Waiting for the other party to submit their review.',
      reviewStatus: 'WAITING',
      review,
    })
  } catch (error: any) {
    if (error.code === 'P2002') {
      return res.status(400).json({ success: false, message: 'You have already submitted a review for this contract.' })
    }
    console.error('[ReviewController] submitReview error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/reviews/contract/:contractId/status
// Returns the review status for the current user on this contract
// ─────────────────────────────────────────────────────────────────────────────
export const getReviewStatus = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId
    const { contractId } = req.params

    // Fetch the contract to verify membership
    const contract = await prisma.contract.findUnique({
      where: { id: contractId },
      include: {
        project: { include: { clientProfile: { select: { userId: true } } } },
        freelancerProfile: { select: { userId: true } },
      },
    })

    if (!contract) {
      return res.status(404).json({ success: false, message: 'Contract not found.' })
    }

    const clientUserId = contract.project.clientProfile.userId
    const freelancerUserId = contract.freelancerProfile.userId

    if (userId !== clientUserId && userId !== freelancerUserId) {
      return res.status(403).json({ success: false, message: 'Access denied.' })
    }

    // Fetch all reviews for this contract
    const reviews = await prisma.review.findMany({
      where: { contractId },
      include: {
        giver: { select: { name: true, profileImage: true } },
        receiver: { select: { name: true, profileImage: true } },
      },
    })

    const myReview = reviews.find((r) => r.giverId === userId) || null
    const theirReview = reviews.find((r) => r.giverId !== userId) || null

    // Determine status
    let reviewStatus: 'PENDING' | 'WAITING' | 'REVEALED'
    if (!myReview && !theirReview) {
      reviewStatus = 'PENDING'
    } else if (myReview && !theirReview) {
      reviewStatus = 'WAITING'
    } else if (!myReview && theirReview) {
      reviewStatus = 'WAITING'
    } else {
      reviewStatus = 'REVEALED'
    }

    // Only return their review if both are revealed
    const theirReviewSafe =
      theirReview?.isRevealed
        ? {
            rating: theirReview.rating,
            comment: theirReview.comment,
            giverName: theirReview.giver.name,
            giverImage: theirReview.giver.profileImage,
            submittedAt: theirReview.submittedAt,
            revealedAt: theirReview.revealedAt,
          }
        : null

    return res.status(200).json({
      success: true,
      reviewStatus,
      myReview: myReview
        ? {
            id: myReview.id,
            rating: myReview.rating,
            comment: myReview.comment,
            isRevealed: myReview.isRevealed,
            submittedAt: myReview.submittedAt,
            reviewDeadline: myReview.reviewDeadline,
          }
        : null,
      theirReview: theirReviewSafe,
    })
  } catch (error) {
    console.error('[ReviewController] getReviewStatus error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/reviews/user/:userId  — Public revealed reviews for a user profile
// ─────────────────────────────────────────────────────────────────────────────
export const getPublicReviewsForUser = async (req: Request, res: Response) => {
  try {
    const { userId } = req.params

    const reviews = await prisma.review.findMany({
      where: { receiverId: userId, isRevealed: true },
      include: {
        giver: { select: { name: true, profileImage: true, role: true } },
        receiver: { select: { name: true } },
      },
      orderBy: { revealedAt: 'desc' },
    })

    // Enrich with project title via contract
    const enriched = await Promise.all(
      reviews.map(async (r) => {
        const contract = await prisma.contract.findUnique({
          where: { id: r.contractId },
          include: { project: { select: { title: true } } },
        })
        return {
          id: r.id,
          rating: r.rating,
          comment: r.comment,
          giverName: r.giver.name,
          giverRole: r.giverRole,
          giverImage: r.giver.profileImage,
          projectTitle: contract?.project?.title || 'Unknown project',
          submittedAt: r.submittedAt,
          revealedAt: r.revealedAt,
        }
      })
    )

    // Aggregate stats
    const avgRating =
      enriched.length > 0
        ? enriched.reduce((sum, r) => sum + r.rating, 0) / enriched.length
        : null

    return res.status(200).json({
      success: true,
      reviews: enriched,
      totalReviews: enriched.length,
      averageRating: avgRating ? Math.round(avgRating * 10) / 10 : null,
    })
  } catch (error) {
    console.error('[ReviewController] getPublicReviewsForUser error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/reviews/my-given  — Reviews the logged-in user has given
// ─────────────────────────────────────────────────────────────────────────────
export const getMyGivenReviews = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId

    const reviews = await prisma.review.findMany({
      where: { giverId: userId, isRevealed: true },
      include: {
        receiver: { select: { name: true, profileImage: true, role: true } },
      },
      orderBy: { submittedAt: 'desc' },
    })

    const enriched = await Promise.all(
      reviews.map(async (r) => {
        const contract = await prisma.contract.findUnique({
          where: { id: r.contractId },
          include: { project: { select: { title: true } } },
        })
        return {
          id: r.id,
          rating: r.rating,
          comment: r.comment,
          receiverName: r.receiver.name,
          receiverImage: r.receiver.profileImage,
          receiverRole: r.receiver.role,
          projectTitle: contract?.project?.title || 'Unknown project',
          contractId: r.contractId,
          submittedAt: r.submittedAt,
          revealedAt: r.revealedAt,
        }
      })
    )

    return res.status(200).json({ success: true, reviews: enriched })
  } catch (error) {
    console.error('[ReviewController] getMyGivenReviews error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/reviews/my-received  — Revealed reviews the logged-in user received
// ─────────────────────────────────────────────────────────────────────────────
export const getMyReceivedReviews = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId

    const reviews = await prisma.review.findMany({
      where: { receiverId: userId, isRevealed: true },
      include: {
        giver: { select: { name: true, profileImage: true, role: true } },
      },
      orderBy: { revealedAt: 'desc' },
    })

    const enriched = await Promise.all(
      reviews.map(async (r) => {
        const contract = await prisma.contract.findUnique({
          where: { id: r.contractId },
          include: { project: { select: { title: true } } },
        })
        return {
          id: r.id,
          rating: r.rating,
          comment: r.comment,
          giverName: r.giver.name,
          giverRole: r.giverRole,
          giverImage: r.giver.profileImage,
          projectTitle: contract?.project?.title || 'Unknown project',
          contractId: r.contractId,
          submittedAt: r.submittedAt,
          revealedAt: r.revealedAt,
        }
      })
    )

    // Per-star breakdown
    const breakdown: Record<number, number> = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 }
    enriched.forEach((r) => { breakdown[r.rating] = (breakdown[r.rating] || 0) + 1 })

    const avgRating =
      enriched.length > 0
        ? enriched.reduce((s, r) => s + r.rating, 0) / enriched.length
        : null

    return res.status(200).json({
      success: true,
      reviews: enriched,
      totalReviews: enriched.length,
      averageRating: avgRating ? Math.round(avgRating * 10) / 10 : null,
      ratingBreakdown: breakdown,
    })
  } catch (error) {
    console.error('[ReviewController] getMyReceivedReviews error:', error)
    return res.status(500).json({ success: false, message: 'Internal server error.' })
  }
}
