import { Router } from 'express'
import { protect } from '../middlewares/auth.middleware'
import {
  submitReview,
  getReviewStatus,
  getPublicReviewsForUser,
  getMyGivenReviews,
  getMyReceivedReviews,
} from '../controllers/review.controller'

const router = Router()

// Submit a review (blind)
router.post('/', protect, submitReview)

// Get review status for current user on a contract
router.get('/contract/:contractId/status', protect, getReviewStatus)

// Reviews the logged-in user gave
router.get('/my-given', protect, getMyGivenReviews)

// Reviews the logged-in user received
router.get('/my-received', protect, getMyReceivedReviews)

// Public revealed reviews for any user (for profile pages)
router.get('/user/:userId', protect, getPublicReviewsForUser)

export default router
