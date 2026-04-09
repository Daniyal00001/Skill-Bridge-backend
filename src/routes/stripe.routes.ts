import { Router } from 'express'
import { protect, requireRole } from '../middlewares/auth.middleware'
import { createPaymentIntent, confirmFundMilestone } from '../controllers/stripe.controller'

const router = Router()

// Create a Stripe PaymentIntent for a milestone (Client only)
router.post('/create-payment-intent', protect, requireRole('CLIENT'), createPaymentIntent)

// After Stripe payment succeeds on frontend, confirm and fund the milestone
router.post('/confirm-fund', protect, requireRole('CLIENT'), confirmFundMilestone)

export default router
